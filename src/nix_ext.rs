// Functions in libc that haven't made it into nix yet
use libc;
use nix::{Errno, Result};
use std::os::unix::io::RawFd;
use std::ffi::CString;

#[inline]
pub fn lsetxattr(
    path: &CString,
    name: &CString,
    value: &CString,
    len: usize,
    flags: i32,
) -> Result<()> {
    let res = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            len,
            flags,
        )
    };
    Errno::result(res).map(drop)
}

#[inline]
pub fn fchdir(fd: RawFd) -> Result<()> {
    let res = unsafe { libc::fchdir(fd) };
    Errno::result(res).map(drop)
}

#[inline]
pub fn setgroups(gids: &[libc::gid_t]) -> Result<()> {
    let res = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
    Errno::result(res).map(drop)
}

#[inline]
pub fn setrlimit(
    resource: libc::c_int,
    soft: libc::c_ulonglong,
    hard: libc::c_ulonglong,
) -> Result<()> {
    let rlim = &libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    let res = unsafe { libc::setrlimit(resource, rlim) };
    Errno::result(res).map(drop)
}

#[inline]
pub fn clearenv() -> Result<()> {
    let res = unsafe { libc::clearenv() };
    Errno::result(res).map(drop)
}

#[cfg(target_env = "gnu")]
#[inline]
pub fn putenv(string: &CString) -> Result<()> {
    // NOTE: gnue takes ownership of the string so we pass it
    //       with into_raw. The docs say this could cause a memory
    //       leak, but we can't claw it back because our execed
    //       program may use the environment.
    let ptr = string.clone().into_raw();
    let res = unsafe { libc::putenv(ptr as *mut libc::c_char) };
    Errno::result(res).map(drop)
}

#[cfg(not(target_env = "gnu"))]
pub fn putenv(string: &CString) -> Result<()> {
    let res = unsafe { libc::putenv(string.as_ptr() as *mut libc::c_char) };
    Errno::result(res).map(drop)
}
