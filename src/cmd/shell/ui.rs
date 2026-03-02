use ratatui::{
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::{App, AppMode};

/// Main render function — draws all UI components
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let chunks = Layout::vertical([
        Constraint::Length(1), // title bar
        Constraint::Min(3),    // output area
        Constraint::Length(3), // input area
        Constraint::Length(1), // status bar
    ])
    .split(area);

    render_title_bar(frame, app, chunks[0]);
    render_output_area(frame, app, chunks[1]);
    render_input_area(frame, app, chunks[2]);
    render_status_bar(frame, app, chunks[3]);

    // Completion popup overlays the output area (drawn last)
    if let AppMode::Completing(ref state) = app.mode {
        render_completion_popup(frame, state, chunks[2]);
    }

    // Set cursor position in input area
    let prompt = app.session.prompt();
    let cursor_x = chunks[2].x + 1 + prompt.len() as u16 + app.cursor_position as u16;
    let cursor_y = chunks[2].y + 1;
    frame.set_cursor_position(Position::new(
        cursor_x.min(chunks[2].x + chunks[2].width - 2),
        cursor_y,
    ));
}

fn render_title_bar(frame: &mut Frame, app: &App, area: Rect) {
    let left = Span::styled(
        " jwt-hack shell ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    // Right side: session indicators
    let alg = Span::styled(
        format!(" {} ", app.session.algorithm),
        Style::default().fg(Color::Green),
    );
    let sep1 = Span::styled(" │ ", Style::default().fg(Color::DarkGray));

    let token_indicator = if app.session.token.is_some() {
        Span::styled("JWT", Style::default().fg(Color::Yellow))
    } else {
        Span::styled("---", Style::default().fg(Color::DarkGray))
    };

    let sep2 = Span::styled(" │ ", Style::default().fg(Color::DarkGray));
    let secret_indicator = if app.session.secret.is_some() {
        Span::styled("●secret", Style::default().fg(Color::Green))
    } else {
        Span::styled("○secret", Style::default().fg(Color::DarkGray))
    };

    // Build the right-side string to calculate padding
    let right_text = format!(
        " {} │ {} │ {} ",
        app.session.algorithm,
        if app.session.token.is_some() {
            "JWT"
        } else {
            "---"
        },
        if app.session.secret.is_some() {
            "●secret"
        } else {
            "○secret"
        },
    );

    let left_text = " jwt-hack shell ";
    let padding_len = area
        .width
        .saturating_sub(left_text.len() as u16 + right_text.len() as u16);
    let padding = Span::raw("─".repeat(padding_len as usize));

    let title_line = Line::from(vec![
        left,
        Span::styled(" ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "─".repeat(padding_len.saturating_sub(2) as usize),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(" ", Style::default().fg(Color::DarkGray)),
        alg,
        sep1,
        token_indicator,
        sep2,
        secret_indicator,
        Span::raw(" "),
    ]);

    // Suppress unused variable warning
    let _ = padding;

    frame.render_widget(
        Paragraph::new(title_line).style(Style::default().bg(Color::Reset)),
        area,
    );
}

fn render_output_area(frame: &mut Frame, app: &App, area: Rect) {
    let output_text = if app.output_lines.lines.is_empty() {
        Text::styled(
            "  Type 'help' for available commands.",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        app.output_lines.clone()
    };

    let total_lines = output_text.lines.len();
    let visible_height = area.height as usize;

    // Calculate scroll offset: auto-scroll to bottom unless user scrolled up
    let max_scroll = total_lines.saturating_sub(visible_height);
    let scroll = if app.scroll_offset > max_scroll {
        max_scroll
    } else {
        app.scroll_offset
    };

    let output = Paragraph::new(output_text)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(output, area);
}

fn render_input_area(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = app.session.prompt();

    let input_line = Line::from(vec![
        Span::styled(
            &prompt,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(&app.input),
    ]);

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let input_widget = Paragraph::new(input_line).block(input_block);
    frame.render_widget(input_widget, area);
}

fn render_status_bar(frame: &mut Frame, _app: &App, area: Rect) {
    let hints = Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow)),
        Span::styled(" complete  │  ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::styled(" history  │  ", Style::default().fg(Color::DarkGray)),
        Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow)),
        Span::styled(" scroll  │  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+C", Style::default().fg(Color::Yellow)),
        Span::styled(" exit", Style::default().fg(Color::DarkGray)),
    ]);

    frame.render_widget(Paragraph::new(hints), area);
}

fn render_completion_popup(
    frame: &mut Frame,
    state: &super::completion::CompletionState,
    input_area: Rect,
) {
    let max_visible = 8.min(state.candidates.len());
    let popup_height = max_visible as u16 + 2; // +2 for borders
    let popup_width = state.candidates.iter().map(|c| c.len()).max().unwrap_or(10) as u16 + 4; // +4 for borders and padding
    let popup_width = popup_width.min(input_area.width);

    // Position popup above the input area
    let popup_area = Rect::new(
        input_area.x + 1,
        input_area.y.saturating_sub(popup_height),
        popup_width,
        popup_height,
    );

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = state
        .candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == state.selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(c.clone(), style))
        })
        .collect();

    let popup = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Completions "),
    );

    frame.render_widget(popup, popup_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::shell::Session;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn test_app() -> App {
        App {
            session: Session::default(),
            input: String::new(),
            cursor_position: 0,
            output_lines: Text::default(),
            scroll_offset: 0,
            history: super::super::history::History::new(100),
            mode: AppMode::Normal,
            should_quit: false,
        }
    }

    #[test]
    fn test_render_does_not_panic() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = test_app();
        terminal
            .draw(|frame| {
                render(frame, &app);
            })
            .unwrap();
    }

    #[test]
    fn test_render_with_output() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app();
        app.output_lines = Text::raw("  > decode\n  Token decoded successfully\n");
        terminal
            .draw(|frame| {
                render(frame, &app);
            })
            .unwrap();
    }

    #[test]
    fn test_render_with_input() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app();
        app.input = "set token eyJ".to_string();
        app.cursor_position = 13;
        terminal
            .draw(|frame| {
                render(frame, &app);
            })
            .unwrap();
    }
}
