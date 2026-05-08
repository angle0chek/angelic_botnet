use std::{io, time::{Duration, Instant}};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell}, // Добавляем Table, Row, Cell
    layout::{Layout, Constraint, Direction}, // Добавляем Layout, Constraint, Direction
    Frame, Terminal,
};
use tokio::sync::watch;
use crate::GlobalStats; // Импортируем GlobalStats из корневого модуля

pub async fn run_tui(stats_receiver: watch::Receiver<GlobalStats>) -> io::Result<()> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);

    loop {
        let current_stats = stats_receiver.borrow().clone(); // Получаем текущую статистику
        terminal.draw(|f| ui(f, &current_stats))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if KeyCode::Char('q') == key.code {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            // app.on_tick(); // Placeholder for app state updates
            last_tick = Instant::now();
        }
    }

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(frame: &mut Frame, stats: &GlobalStats) {
    let size = frame.size();

    // Создаем основной макет с двумя вертикальными блоками
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Для глобальной статистики
            Constraint::Min(0),    // Для карты узлов
        ])
        .split(size);

    // Блок для глобальной статистики
    let stats_block = Block::default()
        .title("Global Stats")
        .borders(Borders::ALL);
    let stats_text = format!(
        "PPS: {}\nTotal Nodes Infected: {}\nScan Throughput: {}\nSuccessful Exploits: {}",
        stats.pps, stats.total_nodes_infected, stats.scan_throughput, stats.successful_exploits
    );
    let stats_paragraph = Paragraph::new(stats_text).block(stats_block);
    frame.render_widget(stats_paragraph, chunks[0]);

    // Блок для карты узлов
    let node_map_block = Block::default()
        .title("Node Map")
        .borders(Borders::ALL);

    let header_cells = ["IP", "Hostname", "CPU Load", "Latency", "Infection Vector"]
        .iter()
        .map(|h| Cell::from(*h));
    let header = Row::new(header_cells);

    let rows = stats.nodes.iter().map(|node| {
        let cells = vec![
            Cell::from(node.ip.clone()),
            Cell::from(node.hostname.clone()),
            Cell::from(format!("{:.2}%", node.cpu_load)),
            Cell::from(format!("{}ms", node.latency)),
            Cell::from(node.infection_vector.clone().unwrap_or_else(|| "N/A".to_string())),
        ];
        Row::new(cells)
    });

    let table = Table::new(rows, [
        Constraint::Percentage(20), // IP
        Constraint::Percentage(20), // Hostname
        Constraint::Percentage(20), // CPU Load
        Constraint::Percentage(20), // Latency
        Constraint::Percentage(20), // Infection Vector
    ])
    .header(header)
    .block(node_map_block)
    .column_spacing(1);

    frame.render_widget(table, chunks[1]);

    // Перемещаем "Press 'q' to quit." в нижний правый угол
    let greeting = Paragraph::new("Press 'q' to quit.");
    frame.render_widget(greeting, size); // Пока оставляем так, потом можно будет точнее позиционировать
}