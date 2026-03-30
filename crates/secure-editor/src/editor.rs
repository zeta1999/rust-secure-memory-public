//! TUI editor built on ratatui + tui-textarea.
//!
//! Supports keybinding modes (normal, nano, emacs, mcedit) and trivial
//! keyword-based syntax highlighting.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Terminal;
use tui_textarea::TextArea;

use std::io::Stdout;
use std::path::PathBuf;

use secure_memory::LockedBuffer;

use crate::file_io;
use crate::highlight;
use crate::KeyMode;

const SALT_SIZE: usize = 16;

/// Editor state.
pub struct Editor<'a> {
    textarea: TextArea<'a>,
    path: Option<PathBuf>,
    key: Option<LockedBuffer>,
    salt: Option<[u8; SALT_SIZE]>,
    modified: bool,
    status_msg: String,
    show_help: bool,
    quit: bool,
    mode: KeyMode,
    /// Emacs: waiting for second key after C-x.
    emacs_cx: bool,
}

impl<'a> Editor<'a> {
    pub fn new(
        path: Option<PathBuf>,
        key: Option<LockedBuffer>,
        salt: Option<[u8; SALT_SIZE]>,
        initial_text: &str,
        mode: KeyMode,
    ) -> Self {
        let lines: Vec<String> = initial_text.lines().map(|l| l.to_string()).collect();
        let lines = if lines.is_empty() {
            vec![String::new()]
        } else {
            lines
        };
        let mut textarea = TextArea::new(lines);
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .title(Self::title_str(&path)),
        );
        textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
        textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));

        // ── Syntax highlighting ──────────────────────────────
        let filename = path
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let ext = path
            .as_ref()
            .and_then(|p| p.extension())
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let language = highlight::detect_language(filename, ext);
        if let Some(pattern) = highlight::keyword_pattern(filename, ext) {
            match textarea.set_search_pattern(pattern) {
                Ok(()) => {
                    textarea.set_search_style(
                        Style::default()
                            .fg(Color::LightYellow)
                            .add_modifier(Modifier::BOLD),
                    );
                }
                Err(_e) => {
                    // Pattern failed to compile — highlighting disabled
                }
            }
        }

        // ── Status bar ───────────────────────────────────────
        let enc_mode = if key.is_some() {
            "encrypted"
        } else {
            "plaintext"
        };
        let mode_name = Self::mode_name(mode);
        let lang_str = language.map(|l| format!(" | {l}")).unwrap_or_default();
        let hints = Self::mode_hints(mode);
        let status_msg = format!(" {enc_mode} | {mode_name}{lang_str} | {hints}");

        Editor {
            textarea,
            path,
            key,
            salt,
            modified: false,
            status_msg,
            show_help: false,
            quit: false,
            mode,
            emacs_cx: false,
        }
    }

    fn title_str(path: &Option<PathBuf>) -> String {
        match path {
            Some(p) => format!(" sedit — {} ", p.display()),
            None => " sedit — [new file] ".to_string(),
        }
    }

    fn mode_name(mode: KeyMode) -> &'static str {
        match mode {
            KeyMode::Normal => "normal",
            KeyMode::Nano => "nano",
            KeyMode::Emacs => "emacs",
            KeyMode::Mcedit => "mcedit",
        }
    }

    fn mode_hints(mode: KeyMode) -> &'static str {
        match mode {
            KeyMode::Normal => "Ctrl-S save | Esc quit | Ctrl-H help",
            KeyMode::Nano => "^O save | ^X quit | ^G help",
            KeyMode::Emacs => "C-x C-s save | C-x C-c quit | C-h help",
            KeyMode::Mcedit => "F2 save | F10 quit | F1 help",
        }
    }

    // ── Event loop ───────────────────────────────────────────

    pub fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| self.draw(f))?;
            if self.quit {
                break;
            }
            if let Event::Key(key_ev) = event::read()? {
                if self.show_help {
                    self.show_help = false;
                    continue;
                }
                if !self.handle_key(key_ev) {
                    self.textarea.input(key_ev);
                    self.modified = true;
                }
            }
        }
        Ok(())
    }

    // ── Key dispatch ─────────────────────────────────────────

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.mode {
            KeyMode::Normal => self.handle_normal(key),
            KeyMode::Nano => self.handle_nano(key),
            KeyMode::Emacs => self.handle_emacs(key),
            KeyMode::Mcedit => self.handle_mcedit(key),
        }
    }

    // ── Normal mode ──────────────────────────────────────────

    fn handle_normal(&mut self, key: KeyEvent) -> bool {
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('q')) | (KeyModifiers::NONE, KeyCode::Esc) => {
                self.try_quit();
                true
            }
            (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
                self.save();
                true
            }
            (KeyModifiers::CONTROL, KeyCode::Char('h')) => {
                self.show_help = true;
                true
            }
            (KeyModifiers::CONTROL, KeyCode::Char('e')) => {
                self.export_plaintext();
                true
            }
            _ => false,
        }
    }

    // ── Nano mode ────────────────────────────────────────────

    fn handle_nano(&mut self, key: KeyEvent) -> bool {
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('x')) => {
                self.try_quit();
                true
            }
            (KeyModifiers::CONTROL, KeyCode::Char('o')) => {
                self.save();
                true
            }
            (KeyModifiers::CONTROL, KeyCode::Char('g')) => {
                self.show_help = true;
                true
            }
            (KeyModifiers::NONE, KeyCode::Esc) => {
                self.try_quit();
                true
            }
            _ => false,
        }
    }

    // ── Emacs mode ───────────────────────────────────────────

    fn handle_emacs(&mut self, key: KeyEvent) -> bool {
        if self.emacs_cx {
            // Second key of a C-x chord
            self.emacs_cx = false;
            match (key.modifiers, key.code) {
                (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
                    self.save();
                    true
                }
                (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                    self.try_quit();
                    true
                }
                _ => {
                    self.status_msg = " C-x cancelled".into();
                    false
                }
            }
        } else {
            match (key.modifiers, key.code) {
                (KeyModifiers::CONTROL, KeyCode::Char('x')) => {
                    self.emacs_cx = true;
                    self.status_msg = " C-x …".into();
                    true
                }
                (KeyModifiers::CONTROL, KeyCode::Char('h')) => {
                    self.show_help = true;
                    true
                }
                (KeyModifiers::NONE, KeyCode::Esc) => {
                    self.try_quit();
                    true
                }
                _ => false,
            }
        }
    }

    // ── MCEdit mode ──────────────────────────────────────────

    fn handle_mcedit(&mut self, key: KeyEvent) -> bool {
        match (key.modifiers, key.code) {
            (_, KeyCode::F(2)) => {
                self.save();
                true
            }
            (_, KeyCode::F(10)) | (KeyModifiers::NONE, KeyCode::Esc) => {
                self.try_quit();
                true
            }
            (_, KeyCode::F(1)) => {
                self.show_help = true;
                true
            }
            _ => false,
        }
    }

    // ── Actions ──────────────────────────────────────────────

    fn try_quit(&mut self) {
        if self.modified {
            self.status_msg = " Unsaved changes! Press again to discard, or save first.".into();
            self.modified = false;
        } else {
            self.quit = true;
        }
    }

    fn save(&mut self) {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => {
                self.status_msg = " No filename. Use: sedit <file>".into();
                return;
            }
        };
        let text = self.textarea.lines().join("\n");
        let result = match (&self.key, &self.salt) {
            (Some(key), Some(salt)) => file_io::save(&path, &text, key, salt),
            _ => file_io::save_plaintext(&path, &text),
        };
        match result {
            Ok(()) => {
                self.modified = false;
                self.status_msg = format!(" Saved: {}", path.display());
            }
            Err(e) => {
                self.status_msg = format!(" Save error: {e}");
            }
        }
    }

    fn export_plaintext(&mut self) {
        let path = match &self.path {
            Some(p) => {
                let mut p = p.clone();
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                p.set_file_name(format!("{name}.plain"));
                p
            }
            None => {
                self.status_msg = " No filename for export.".into();
                return;
            }
        };
        let text = self.textarea.lines().join("\n");
        match file_io::save_plaintext(&path, &text) {
            Ok(()) => {
                self.status_msg = format!(" Exported plaintext: {}", path.display());
            }
            Err(e) => {
                self.status_msg = format!(" Export error: {e}");
            }
        }
    }

    // ── Drawing ──────────────────────────────────────────────

    fn draw(&mut self, f: &mut ratatui::Frame) {
        if self.show_help {
            self.draw_help(f);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(f.area());

        let mod_indicator = if self.modified { " [+]" } else { "" };
        let title = format!("{}{}", Self::title_str(&self.path), mod_indicator);
        self.textarea
            .set_block(Block::default().borders(Borders::ALL).title(title));

        f.render_widget(&self.textarea, chunks[0]);

        let status = Paragraph::new(Line::from(vec![Span::styled(
            &self.status_msg,
            Style::default().fg(Color::Black).bg(Color::White),
        )]));
        f.render_widget(status, chunks[1]);
    }

    fn draw_help(&self, f: &mut ratatui::Frame) {
        let mode_lines = match self.mode {
            KeyMode::Normal => vec![
                "  Ctrl-S       Save (encrypted)",
                "  Esc / Ctrl-Q Quit",
                "  Ctrl-H       Help",
                "  Ctrl-E       Export plaintext",
            ],
            KeyMode::Nano => vec![
                "  ^O           Save (Write Out)",
                "  ^X / Esc     Quit",
                "  ^G           Help",
            ],
            KeyMode::Emacs => vec![
                "  C-x C-s      Save",
                "  C-x C-c      Quit",
                "  Esc          Quit",
                "  C-h          Help",
            ],
            KeyMode::Mcedit => vec![
                "  F2           Save",
                "  F10 / Esc    Quit",
                "  F1           Help",
            ],
        };

        let mode_name = Self::mode_name(self.mode);
        let mut help: Vec<&str> = vec![
            "",
            &"  ╔══════════════════════════════════════╗",
            &"  ║         sedit — Key Bindings          ║",
            &"  ╠══════════════════════════════════════╣",
        ];
        help.extend(&mode_lines);
        help.extend(&[
            "  ║                                        ║",
            "  Arrow keys / Home / End   Navigate",
            "  Backspace / Delete        Edit",
            "  Enter                     New line",
            "",
            "  Press any key to dismiss …",
            "",
        ]);

        let title = format!(" Help — {mode_name} mode ");
        let lines: Vec<Line> = help
            .iter()
            .map(|l| Line::from(Span::styled(*l, Style::default().fg(Color::Cyan))))
            .collect();

        let para = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(para, f.area());
    }
}
