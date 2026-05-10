use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

use crate::types::{HostResult, PortStatus};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct TuiState {
    hosts: Vec<HostResult>,
    expanded: Vec<bool>,
    /// Absolute index into the flat display list
    selected: usize,
    /// First row index that is visible (for scrolling)
    scroll_offset: usize,
}

#[derive(Clone)]
enum DisplayRow {
    Host { host_idx: usize },
    Port { host_idx: usize, port_idx: usize },
}

impl TuiState {
    fn new(hosts: Vec<HostResult>) -> Self {
        let n = hosts.len();
        Self { hosts, expanded: vec![false; n], selected: 0, scroll_offset: 0 }
    }

    fn display_rows(&self) -> Vec<DisplayRow> {
        let mut rows = Vec::new();
        for (i, host) in self.hosts.iter().enumerate() {
            rows.push(DisplayRow::Host { host_idx: i });
            if self.expanded[i] {
                for j in 0..host.ports.len() {
                    rows.push(DisplayRow::Port { host_idx: i, port_idx: j });
                }
            }
        }
        rows
    }

    fn clamp_selected(&mut self) {
        let len = self.display_rows().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Keep scroll window centred around the selection.
    fn adjust_scroll(&mut self, visible_height: usize) {
        let vh = visible_height.max(1);
        let total = self.display_rows().len();
        // Cap scroll_offset so the last page is fully used.
        let max_offset = total.saturating_sub(vh);
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + vh {
            self.scroll_offset = self.selected + 1 - vh;
        }
        self.scroll_offset = self.scroll_offset.min(max_offset);
    }

    fn toggle_selected(&mut self) {
        let rows = self.display_rows();
        if let Some(row) = rows.get(self.selected) {
            let host_idx = match row {
                DisplayRow::Host { host_idx } | DisplayRow::Port { host_idx, .. } => *host_idx,
            };
            self.expanded[host_idx] = !self.expanded[host_idx];
            // If we collapsed while on a port row, snap selection to the host row.
            if !self.expanded[host_idx] {
                let new_rows = self.display_rows();
                self.selected = new_rows
                    .iter()
                    .position(|r| matches!(r, DisplayRow::Host { host_idx: h } if *h == host_idx))
                    .unwrap_or(self.selected);
            }
        }
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self) {
        let total = self.display_rows().len();
        if self.selected + 1 < total {
            self.selected += 1;
        }
    }

    /// Expand selected host and jump into its first port.
    fn move_right(&mut self) {
        let rows = self.display_rows();
        if let Some(DisplayRow::Host { host_idx }) = rows.get(self.selected) {
            let hi = *host_idx;
            if !self.expanded[hi] {
                self.expanded[hi] = true;
            }
            if !self.hosts[hi].ports.is_empty() {
                self.selected += 1; // first port row is right after the host row
            }
        }
    }

    /// Collapse (or jump to parent host) from a port row.
    fn move_left(&mut self) {
        let rows = self.display_rows();
        match rows.get(self.selected) {
            Some(DisplayRow::Port { host_idx, .. }) => {
                let hi = *host_idx;
                self.expanded[hi] = false;
                let new_rows = self.display_rows();
                self.selected = new_rows
                    .iter()
                    .position(|r| matches!(r, DisplayRow::Host { host_idx: h } if *h == hi))
                    .unwrap_or(self.selected);
            }
            Some(DisplayRow::Host { host_idx }) => {
                self.expanded[*host_idx] = false;
            }
            None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn alive_style(alive: Option<bool>) -> Style {
    match alive {
        Some(true) => Style::default().fg(Color::Green),
        Some(false) => Style::default().fg(Color::Red),
        None => Style::default().fg(Color::DarkGray),
    }
}

fn port_status_style(s: &PortStatus) -> Style {
    match s {
        PortStatus::Open => Style::default().fg(Color::Green),
        PortStatus::Closed => Style::default().fg(Color::Red),
        PortStatus::Filtered => Style::default().fg(Color::Yellow),
    }
}

/// Build a single ratatui Row. We avoid setting cell-level backgrounds so the
/// row-level highlight bg is never clobbered.
fn make_row(
    row: &DisplayRow,
    hosts: &[HostResult],
    expanded: &[bool],
    is_selected: bool,
) -> Row<'static> {
    let sel_bg = if is_selected {
        Style::default().bg(Color::Rgb(50, 50, 100)).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    match row {
        DisplayRow::Host { host_idx } => {
            let host = &hosts[*host_idx];
            let arrow = if expanded[*host_idx] { "▼ " } else { "▶ " };
            let alive_str = match host.alive {
                Some(true) => "up",
                Some(false) => "down",
                None => "?",
            };
            let open_count =
                host.ports.iter().filter(|p| p.status == PortStatus::Open).count();
            let total = host.ports.len();

            let arrow_fg = if is_selected {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Cyan)
            };
            let ip_fg = if is_selected {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().add_modifier(Modifier::BOLD)
            };
            let alive_fg = if is_selected {
                Style::default().fg(match host.alive {
                    Some(true) => Color::LightGreen,
                    Some(false) => Color::LightRed,
                    None => Color::Gray,
                })
            } else {
                alive_style(host.alive)
            };

            Row::new(vec![
                Cell::from(arrow.to_owned()).style(arrow_fg),
                Cell::from(host.ip.to_string()).style(ip_fg),
                Cell::from(alive_str.to_owned()).style(alive_fg),
                Cell::from(format!("{}/{}", open_count, total)),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])
            .style(sel_bg)
        }

        DisplayRow::Port { host_idx, port_idx } => {
            let port = &hosts[*host_idx].ports[*port_idx];
            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(30, 60, 30)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let status_fg = if is_selected {
                match port.status {
                    PortStatus::Open => Style::default().fg(Color::LightGreen),
                    PortStatus::Closed => Style::default().fg(Color::LightRed),
                    PortStatus::Filtered => Style::default().fg(Color::LightYellow),
                }
            } else {
                port_status_style(&port.status)
            };
            let port_fg = if is_selected {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            let svc = port.service.as_deref().unwrap_or("").to_owned();
            let ver = port.version.as_deref().unwrap_or("").to_owned();

            Row::new(vec![
                Cell::from(""),
                Cell::from(format!("  └─ {}", port.port)).style(port_fg),
                Cell::from(""),
                Cell::from(""),
                Cell::from(port.status.to_string()).style(status_fg),
                Cell::from(svc),
                Cell::from(ver),
            ])
            .style(row_style)
        }
    }
}

fn render(state: &TuiState, f: &mut ratatui::Frame, inner_height: usize) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    // Build visible rows from the pre-computed scroll window.
    let all_rows = state.display_rows();
    let total = all_rows.len();

    let visible: Vec<Row> = all_rows
        .iter()
        .enumerate()
        .skip(state.scroll_offset)
        .take(inner_height)
        .map(|(abs_idx, row)| make_row(row, &state.hosts, &state.expanded, abs_idx == state.selected))
        .collect();

    let open_total: usize = state
        .hosts
        .iter()
        .map(|h| h.ports.iter().filter(|p| p.status == PortStatus::Open).count())
        .sum();

    let title = format!(
        " rmap  hosts={}  open={}  [{}/{}] ",
        state.hosts.len(),
        open_total,
        state.selected + 1,
        total.max(1),
    );

    let header = Row::new(vec![
        Cell::from(""),
        Cell::from("IP Address"),
        Cell::from("Status"),
        Cell::from("Ports"),
        Cell::from("Port Status"),
        Cell::from("Service"),
        Cell::from("Version"),
    ])
    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
    .height(1);

    let table = Table::new(
        visible,
        [
            Constraint::Length(3),
            Constraint::Min(17),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(table, chunks[0]);

    // Footer / key-hint bar
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓ / jk", Style::default().fg(Color::Yellow)),
        Span::raw(": move  "),
        Span::styled("Enter/Spc", Style::default().fg(Color::Yellow)),
        Span::raw(": expand/collapse  "),
        Span::styled("→ / ←", Style::default().fg(Color::Yellow)),
        Span::raw(": open/close  "),
        Span::styled("a", Style::default().fg(Color::Yellow)),
        Span::raw(": toggle all  "),
        Span::styled("q / Esc", Style::default().fg(Color::Yellow)),
        Span::raw(": quit "),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 20)));

    f.render_widget(help, chunks[1]);
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

pub fn run_tui(hosts: Vec<HostResult>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    // Restore terminal even on panic.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = TuiState::new(hosts);

    let result = run_loop(&mut terminal, &mut state);

    // Always restore the terminal.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
) -> io::Result<()> {
    loop {
        // Compute visible height from terminal dimensions BEFORE drawing.
        let term_height = terminal.size()?.height as usize;
        // Layout: 1 footer line, table with 2 border rows + 1 header row = 3
        let inner_height = term_height.saturating_sub(4).max(1);
        state.adjust_scroll(inner_height);

        terminal.draw(|f| render(state, f, inner_height))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Only handle Press (and Repeat for held keys); ignore Release.
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                    KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                    KeyCode::Right | KeyCode::Char('l') => state.move_right(),
                    KeyCode::Left | KeyCode::Char('h') => state.move_left(),
                    KeyCode::Enter | KeyCode::Char(' ') => state.toggle_selected(),
                    KeyCode::Char('a') => {
                        let all = state.expanded.iter().all(|&e| e);
                        state.expanded.iter_mut().for_each(|e| *e = !all);
                        state.clamp_selected();
                    }
                    KeyCode::Home => state.selected = 0,
                    KeyCode::End => {
                        let n = state.display_rows().len();
                        if n > 0 {
                            state.selected = n - 1;
                        }
                    }
                    KeyCode::PageUp => {
                        state.selected = state.selected.saturating_sub(inner_height);
                    }
                    KeyCode::PageDown => {
                        let n = state.display_rows().len();
                        state.selected = (state.selected + inner_height).min(n.saturating_sub(1));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

