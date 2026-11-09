//! Reading a secret line from the terminal without echo.

use std::io::BufRead;

use zeroize::Zeroizing;

/// Reads one line from the terminal without echo.
#[cfg(unix)]
pub fn read_hidden() -> std::io::Result<Zeroizing<String>> {
    // SAFETY: termios calls on stdin with a struct that tcgetattr fills in.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut quiet = old;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ICANON | libc::ISIG;
    quiet.c_iflag |= libc::ICRNL;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &quiet) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::stdin().lock().read_line(&mut line);
    // SAFETY: restores the settings read above.
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    r?;
    Ok(line)
}

/// Reads one line from the console without echo.
#[cfg(windows)]
pub fn read_hidden() -> std::io::Result<Zeroizing<String>> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    // SAFETY: console calls on the process's own stdin handle.
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut old = 0;
    if unsafe { GetConsoleMode(h, &mut old) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { SetConsoleMode(h, old & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::stdin().lock().read_line(&mut line);
    // SAFETY: restores the mode read above.
    unsafe { SetConsoleMode(h, old) };
    r?;
    Ok(line)
}

/// A hidden prompt on a terminal, otherwise one line from stdin.
pub fn read_secret(label: &str) -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    let line = if std::io::stdin().is_terminal() {
        eprint!("{label}");
        let r = read_hidden();
        eprintln!();
        r.map_err(|e| e.to_string())?
    } else {
        let mut line = Zeroizing::new(String::new());
        let n = std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF".into());
        }
        line
    };
    Ok(Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}
