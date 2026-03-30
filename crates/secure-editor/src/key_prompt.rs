//! Key prompt — collect the encryption/decryption password at startup.
//!
//! Returns the raw password in a [`LockedBuffer`]. Key derivation happens
//! later once the per-file salt is known (see [`file_io`](crate::file_io)).

use secure_memory::LockedBuffer;
use zeroize::Zeroize;

/// Prompt for a password, returning it in a [`LockedBuffer`].
///
/// * `from_stdin` — read the first line of stdin instead of prompting.
/// * `file_exists` — if false, asks twice and checks match.
pub fn prompt_password(from_stdin: bool, file_exists: bool) -> anyhow::Result<LockedBuffer> {
    if from_stdin {
        return password_from_stdin();
    }

    if file_exists {
        let mut pass = rpassword::prompt_password("Decryption key: ")?;
        let buf = LockedBuffer::from_bytes(pass.as_bytes())?;
        pass.zeroize();
        Ok(buf)
    } else {
        loop {
            let mut p1 = rpassword::prompt_password("New encryption key: ")?;
            let mut p2 = rpassword::prompt_password("Confirm encryption key: ")?;

            if p1 != p2 {
                p1.zeroize();
                p2.zeroize();
                eprintln!("Keys do not match. Try again.");
                continue;
            }

            let buf = LockedBuffer::from_bytes(p1.as_bytes())?;
            p1.zeroize();
            p2.zeroize();
            return Ok(buf);
        }
    }
}

fn password_from_stdin() -> anyhow::Result<LockedBuffer> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim_end();
    let buf = LockedBuffer::from_bytes(trimmed.as_bytes())?;
    line.zeroize();
    Ok(buf)
}
