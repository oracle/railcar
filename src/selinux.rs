use errors::*;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, write};
use nix_ext::lsetxattr;
use std::ffi::CString;

const EXEC_PATH: &'static str = "/proc/self/attr/exec";

pub fn setexeccon(label: &str) -> Result<()> {
    let fd = open(EXEC_PATH, OFlag::O_RDWR, Mode::empty())?;
    defer!(close(fd).unwrap());
    write(fd, label.as_bytes())?;
    Ok(())
}

const XATTR_NAME: &'static str = "security.selinux";

pub fn setfilecon(file: &str, label: &str) -> Result<()> {
    let path = CString::new(file)?;
    let name = CString::new(XATTR_NAME)?;
    let value = CString::new(label)?;
    lsetxattr(&path, &name, &value, label.len(), 0)?;
    Ok(())
}
