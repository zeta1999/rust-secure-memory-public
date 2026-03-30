//! Application orchestration: key prompt → load file → run editor → cleanup.

use std::io::{self, stdout};
use std::path::PathBuf;

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::editor::Editor;
use crate::file_io;
use crate::key_prompt;
use crate::KeyMode;

pub fn run(
    path: Option<PathBuf>,
    key_stdin: bool,
    plaintext_mode: bool,
    mode: KeyMode,
) -> anyhow::Result<()> {
    // ── 1. Resolve key, salt, and file content ───────────────

    let file_exists = path.as_ref().is_some_and(|p| p.exists());

    let (initial_text, key, salt) = if plaintext_mode {
        let text = if file_exists {
            file_io::load_plaintext(path.as_ref().unwrap())?
        } else {
            String::new()
        };
        (text, None, None)
    } else if file_exists {
        if file_io::is_encrypted(path.as_ref().unwrap())? {
            // Existing encrypted file — read salt from header, derive key
            let password = key_prompt::prompt_password(key_stdin, true)?;
            let (text, key, salt) = file_io::load(path.as_ref().unwrap(), &password)?;
            (text, Some(key), Some(salt))
        } else {
            // Existing plaintext file
            eprintln!("File is plaintext. Opening without encryption.");
            let text = file_io::load_plaintext(path.as_ref().unwrap())?;
            (text, None, None)
        }
    } else {
        // New file — generate random salt, derive key
        let password = key_prompt::prompt_password(key_stdin, false)?;
        let salt = file_io::new_salt();
        let key = file_io::derive_file_key(&password, &salt)?;
        (String::new(), Some(key), Some(salt))
    };

    // ── 2. Set up terminal ───────────────────────────────────

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ── 3. Run editor ────────────────────────────────────────

    let mut editor = Editor::new(path, key, salt, &initial_text, mode);
    let result = editor.run(&mut terminal);

    // ── 4. Restore terminal ──────────────────────────────────

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}
