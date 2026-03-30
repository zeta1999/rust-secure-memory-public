mod app;
mod editor;
mod file_io;
mod highlight;
mod key_prompt;

use std::path::PathBuf;

use clap::Parser;

/// sedit — secure encrypted text editor
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// File to open or create
    file: Option<PathBuf>,

    /// Read encryption key from stdin (first line) instead of interactive prompt
    #[arg(long)]
    key_stdin: bool,

    /// Open file as plaintext (no encryption)
    #[arg(long)]
    plaintext: bool,

    /// Keybinding mode
    #[arg(long, value_enum, default_value_t = KeyMode::Normal)]
    mode: KeyMode,
}

/// Keybinding compatibility modes.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum KeyMode {
    /// Default: Esc quit, Ctrl-S save, Ctrl-H help
    Normal,
    /// nano-style: Ctrl-X quit, Ctrl-O save, Ctrl-G help
    Nano,
    /// Emacs-style: C-x C-c quit, C-x C-s save
    Emacs,
    /// MCEdit-style: F10 quit, F2 save, F1 help
    Mcedit,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    app::run(cli.file, cli.key_stdin, cli.plaintext, cli.mode)
}
