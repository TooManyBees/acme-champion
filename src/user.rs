use libc::{geteuid, getpwnam, passwd, setuid};
use std::ffi::CString;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum SetUserError {
    InvalidUsername(String),
    NoSuchUser(String),
    SetUidError(io::Error),
}

impl Error for SetUserError {}

impl fmt::Display for SetUserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SetUserError::InvalidUsername(u) => write!(f, "invalid username: {}", u),
            SetUserError::NoSuchUser(u) => write!(f, "no such user: {}", u),
            SetUserError::SetUidError(e) => write!(f, "error invoking setuid: {}", e),
        }
    }
}

pub fn set_user(username: &str) -> Result<(), SetUserError> {
    if unsafe { geteuid() != 0 } {
        log::warn!("process is not running as superuser, ignoring user change");
        return Ok(());
    }

    let username_c =
        CString::new(username).map_err(|_| SetUserError::InvalidUsername(username.to_string()))?;

    unsafe {
        let pwd_ptr: *mut passwd = getpwnam(username_c.as_ptr());
        let pwd = match pwd_ptr.as_ref() {
            Some(pwd) => pwd,
            None => return Err(SetUserError::NoSuchUser(username.to_string())),
        };

        let result = setuid(pwd.pw_uid);
        if result != 0 {
            let error = io::Error::last_os_error();
            return Err(SetUserError::SetUidError(error));
        }
    }

    Ok(())
}
