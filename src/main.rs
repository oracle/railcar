#![recursion_limit = "1024"]
#![cfg_attr(feature = "nightly", feature(start))]
#![cfg_attr(feature = "nightly", feature(alloc_system))]
#[cfg(feature = "nightly")]
extern crate alloc_system;

extern crate caps;
#[macro_use]
extern crate error_chain;
extern crate getopts;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate nix;
extern crate num_traits;
extern crate prctl;
#[macro_use]
extern crate scopeguard;
extern crate seccomp_sys;
extern crate oci;

mod capabilities;
mod cgroups;
mod errors;
mod logger;
mod sync;
mod mounts;
mod seccomp;
mod selinux;
mod signals;
mod nix_ext;

use errors::*;
use getopts::Options;
use lazy_static::initialize;
use nix::fcntl::{open, OFlag, O_RDWR, O_RDONLY, O_WRONLY, O_CLOEXEC, O_NOCTTY};
use nix::poll::{poll, PollFd, POLLIN, POLLHUP, POLLNVAL, EventFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sched::{CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS};
use nix::sched::{CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWCGROUP};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::stat::{Mode, fstat};
use nix::sys::wait::{waitpid, WaitStatus, WNOHANG};
use nix::unistd::{close, fork, ForkResult, pipe2, read, write, dup2, setsid};
use nix::unistd::{setresuid, setresgid, chdir, sethostname, execvp, getpid};
use nix::Errno;
use nix_ext::{setgroups, setrlimit, clearenv, putenv};
use oci::{Spec, Linux, LinuxIDMapping, LinuxRlimit};
use oci::{LinuxDevice, LinuxDeviceType};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, create_dir, create_dir_all, remove_dir_all, canonicalize};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::io::{RawFd, FromRawFd};
use sync::Cond;

lazy_static! {
    static ref DEFAULT_DEVICES: Vec<LinuxDevice> = {
        let mut v = Vec::new();
        v.push(LinuxDevice{
            path: "/dev/null".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 3,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice{
            path: "/dev/zero".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 5,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice{
            path: "/dev/full".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 7,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice{
            path: "/dev/tty".to_string(),
            typ: LinuxDeviceType::c,
            major: 5,
            minor: 0,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice{
            path: "/dev/urandom".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 9,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice{
            path: "/dev/random".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 8,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v
    };
}

lazy_static! {
    static ref NAMESPACES: HashMap<CloneFlags, &'static str> = {
        let mut result = HashMap::new();
        result.insert(CLONE_NEWIPC, "ipc");
        result.insert(CLONE_NEWUTS, "uts");
        result.insert(CLONE_NEWNET, "net");
        result.insert(CLONE_NEWPID, "pid");
        result.insert(CLONE_NEWNS, "mnt");
        result.insert(CLONE_NEWCGROUP, "cgroup");
        result.insert(CLONE_NEWUSER, "user");
        result
    };
}

const CONFIG: &'static str = "config.json";
const INIT_PID: &'static str = "init.pid";
const PROCESS_PID: &'static str = "process.pid";

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn print_usage(program: &str, opts: &Options) {
    let u = format!(
        r#"Usage: {} [options] <command> <container-id> [bundle-dir='.']

Commands:

    run     run a container
    create  create a container (to be started later)
    start   start a (previously created) container
    state   get the (json) state of a (previously created) container
    kill    signal a (previously created) container
    delete  delete a (previously created) container
    ps      list processes in a (previously created) container"#,
        program
    );
    print!("{}", opts.usage(&u));
}

#[cfg(feature = "nightly")]
static mut ARGC: isize = 0 as isize;
#[cfg(feature = "nightly")]
static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

// using start instead of main to get direct access to arg0
#[cfg(feature = "nightly")]
#[start]
fn start(argc: isize, argv: *const *const u8) -> isize {
    unsafe {
        // store args so we can access them later
        ARGC = argc;
        ARGV = argv as *mut *mut i8;
    }

    // enable stack unwinding
    if std::panic::catch_unwind(main).is_err() {
        101
    } else {
        0
    }
}

// only show backtrace in debug mode
#[cfg(not(debug_assertions))]
fn print_backtrace(_: &Error) {}

#[cfg(debug_assertions)]
fn print_backtrace(e: &Error) {
    match e.backtrace() {
        Some(backtrace) => error!("{:?}", backtrace),
        None => error!("to view backtrace, use RUST_BACKTRACE=1"),
    }
}

#[cfg(feature = "nightly")]
fn get_args() -> Vec<String> {
    // we parse args directly since we didn't call the runtime
    // lang_start() function to parse them.
    let mut args = Vec::new();
    unsafe {
        for i in 0..ARGC {
            let cstr = std::ffi::CStr::from_ptr(*ARGV.offset(i));
            args.push(cstr.to_string_lossy().into_owned());
        }
    }
    args
}

#[cfg(not(feature = "nightly"))]
fn get_args() -> Vec<String> {
    std::env::args().collect()
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    let pid = getpid();
    if let Err(ref e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        print_backtrace(e);
        // if we are the top level thread, kill all children
        if pid == getpid() {
            signals::signal_children(Signal::SIGTERM).unwrap();
        }
        ::std::process::exit(1);
    }
    ::std::process::exit(0);
}

fn run() -> Result<()> {
    let args = get_args();

    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help and exit");
    opts.optflag("V", "version", "output version information and exit");
    opts.optflag("v", "verbose", "enable more verbose logging");
    opts.optflag("n", "no-init", "do not create an init process");
    opts.optflag("o", "only-init", "do not exec process (exits on signal)");
    opts.optflag("d", "daemonize", "daemonize the process");
    opts.optopt(
        "b",
        "bundle",
        "bundle directory (defaults to '.')",
        "BUNDLE",
    );
    opts.optopt(
        "r",
        "root",
        "dir for state (defaults to '/run/railcar')",
        "ROOT",
    );
    opts.optopt(
        "p",
        "pid-file",
        "additional location to write pid",
        "PID-FILE",
    );
    opts.optopt("c", "console", "console to use", "CONSOLE");
    opts.optopt("f", "format", "compatibility (ignored)", "IGNORED");
    opts.optopt("", "log", "compatibility (ignored)", "IGNORED");
    opts.optopt("", "log-format", "compatibility (ignored)", "IGNORED");
    opts.optflag("", "all", "compatibility (ignored)");

    let matches = opts.parse(&args[1..]).chain_err(
        || "unable to parse options",
    )?;

    if matches.opt_present("h") {
        println!("railcar - run container from oci runtime spec");
        println!("");
        print_usage(program, &opts);
        return Ok(());
    }

    if matches.opt_present("V") {
        println!("{} version: {}", program, VERSION.unwrap_or("unknown"));
        return Ok(());
    }

    if matches.free.len() < 2 {
        print_usage(program, &opts);
        bail!("command is required");
    }

    let level = if matches.opt_present("v") {
        log::LogLevelFilter::Debug
    } else {
        log::LogLevelFilter::Info
    };


    let _ = log::set_logger(|max_log_level| {
        max_log_level.set(level);
        Box::new(logger::SimpleLogger)
    });

    let command = &matches.free[0];
    let id = &matches.free[1];
    if id.contains("..") || id.contains('/') {
        bail!("id {} may cannot contain '..' or '/'", id);
    }
    let state_dir = matches.opt_str("r")
        .unwrap_or_else(|| "/run/railcar".to_string());
    debug!("ensuring railcar state dir {}", &state_dir);
    let chain = || format!("ensuring railcar state dir {} failed", &state_dir);
    create_dir_all(&state_dir).chain_err(chain)?;
    match command.as_ref() {
        "state" => cmd_state(id, &state_dir),
        "create" => cmd_create(id, &state_dir, &matches),
        "start" => cmd_start(id, &state_dir, &matches),
        "kill" => cmd_kill(id, &state_dir, &matches),
        "ps" => cmd_ps(id, &state_dir),
        "delete" => cmd_delete(id, &state_dir),
        // state dir is ignored for run
        "run" => cmd_run(id, &matches),
        _ => bail!("command not recognized"),
    }
}

#[inline]
fn instance_dir(id: &str, state_dir: &str) -> String {
    format!("{}/{}", state_dir, id)
}

fn state(id: &str, status: &str, pid: i32, bundle: &str) -> oci::State {
    oci::State {
        version: "0.2.0".to_string(),
        id: id.to_string(),
        status: status.to_string(),
        pid: pid,
        bundle: bundle.to_string(),
        annotations: HashMap::new(),
    }
}

// must be in instance_dir
fn get_init_pid() -> Result<(i32)> {
    let mut pid = -1;
    if let Ok(mut f) = File::open(INIT_PID) {
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(process_pid) = result.parse::<i32>() {
            pid = process_pid;
        }
    }
    Ok(pid)
}

fn state_from_dir(id: &str, state_dir: &str) -> Result<(oci::State)> {
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(
        || format!("instance {} doesn't exist", id),
    )?;
    let mut status = "creating";
    let mut root = String::new();
    let pid = get_init_pid()?;
    if let Ok(spec) = Spec::load(CONFIG) {
        root = spec.root.path.to_owned();
        status = "created";
        if let Ok(mut f) = File::open(PROCESS_PID) {
            status = "running";
            let mut result = String::new();
            f.read_to_string(&mut result)?;
            if let Ok(process_pid) = result.parse::<i32>() {
                if signals::signal_process(process_pid, None).is_err() {
                    status = "stopped";
                }
            } else {
                warn!("invalid process pid: {}", result);
            }
        } else {
            warn!("could not open process pid");
        }
    }
    let st = state(id, status, pid, &root);
    Ok(st)
}


fn cmd_state(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing state");
    let st = state_from_dir(id, state_dir)?;
    println!("{}", st.to_string().chain_err(|| "invalid state")?);
    Ok(())
}

fn cmd_create(
    id: &str,
    state_dir: &str,
    matches: &getopts::Matches,
) -> Result<()> {
    debug!("Performing create");
    let bundle = if matches.free.len() >= 3 {
        matches.free[2].clone()
    } else {
        matches.opt_str("b").unwrap_or_else(|| ".".to_string())
    };
    chdir(&*bundle).chain_err(
        || format!("failed to chdir to {}", bundle),
    )?;
    let spec = Spec::load(CONFIG).chain_err(
        || format!("failed to load {}", CONFIG),
    )?;

    let rootfs = canonicalize(&spec.root.path)
        .chain_err(|| format!{"failed to find root path {}", &spec.root.path})?
        .to_string_lossy()
        .into_owned();

    let dir = instance_dir(id, state_dir);
    debug!("creating state dir {}", &dir);
    if let Err(e) = create_dir(&dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let chain = || format!("creating state dir {} failed", &dir);
            Err(e).chain_err(chain)?;
        }
        bail!("Container with id {} already exists", id);
    }

    chdir(&*dir).chain_err(
        || format!("failed to chdir to {}", &dir),
    )?;

    let console = matches.opt_str("c").unwrap_or_default();
    if console != "" {
        let lnk = format!("{}/console", dir);
        symlink(&console, lnk)?;
    }
    let pidfile = matches.opt_str("p").unwrap_or_default();

    let child_pid =
        run_container(id, &rootfs, &spec, -1, true, true, true, -1)?;
    if child_pid != -1 {
        debug!("writing init pid file {}", child_pid);
        let mut f = File::create(INIT_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
        if pidfile != "" {
            debug!("writing process {} pid to file {}", child_pid, pidfile);
            let mut f = File::create(pidfile)?;
            f.write_all(child_pid.to_string().as_bytes())?;
        }
        let linux = spec.linux.as_ref().unwrap();
        // update namespaces to enter only
        let mut namespaces = Vec::new();
        for ns in &linux.namespaces {
            let space = CloneFlags::from_bits_truncate(ns.typ as i32);
            if let Some(name) = NAMESPACES.get(&space) {
                let path = format!("/proc/{}/ns/{}", child_pid, name);
                let n = oci::LinuxNamespace {
                    typ: ns.typ,
                    path: path,
                };
                namespaces.push(n);
            }
        }
        let updated_linux = oci::Linux {
            uid_mappings: linux.uid_mappings.clone(),
            gid_mappings: linux.gid_mappings.clone(),
            sysctl: HashMap::new(),
            resources: None,
            cgroups_path: linux.cgroups_path.to_owned(),
            namespaces: namespaces,
            devices: Vec::new(),
            seccomp: None,
            rootfs_propagation: "".to_string(),
            masked_paths: Vec::new(),
            readonly_paths: Vec::new(),
            mount_label: "".to_string(),
        };
        let updated = Spec {
            version: spec.version,
            platform: spec.platform,
            process: spec.process,
            root: oci::Root {
                path: rootfs,
                readonly: spec.root.readonly,
            },
            hostname: "".to_string(), // hostname not needed
            mounts: Vec::new(), // remove mounts
            hooks: spec.hooks,
            annotations: spec.annotations,
            linux: Some(updated_linux),
            solaris: spec.solaris,
            windows: spec.windows,
        };
        debug!("writing updated config");
        updated.save(CONFIG)
            .chain_err(|| format!("failed to save {}", CONFIG))?;
    }
    Ok(())
}

fn cmd_start(
    id: &str,
    state_dir: &str,
    matches: &getopts::Matches,
) -> Result<()> {
    debug!("Performing start");

    // we use instance dir for config written out by create
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(
        || format!("instance {} doesn't exist", id),
    )?;

    let spec = Spec::load(CONFIG).chain_err(
        || format!("failed to load {}", CONFIG),
    )?;

    let console = format!("{}/console", dir);
    let consolefd = match open(&*console, O_NOCTTY | O_RDWR, Mode::empty()) {
        Err(e) => {
            if e.errno() != Errno::ENOENT {
                let msg = format!("failed to open {}", console);
                return Err(e).chain_err(|| msg)?;
            }
            -1
        }
        Ok(fd) => fd,
    };
    let mut init = !matches.opt_present("n");
    let init_pid = get_init_pid()?;
    if init_pid != -1 {
        // NOTE: if init was set but we already have an init pid,
        //       don't attempt to create another init.
        init = false;
    }


    let child_pid = run_container(
        id,
        &spec.root.path,
        &spec,
        init_pid,
        init,
        false,
        true,
        consolefd,
    )?;
    if child_pid != -1 {
        debug!("writing process {} pid file", child_pid);
        let mut f = File::create(PROCESS_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
    }
    Ok(())
}

fn cmd_kill(
    id: &str,
    state_dir: &str,
    matches: &getopts::Matches,
) -> Result<()> {
    debug!("Performing kill");
    let signal = if matches.free.len() > 2 {
        signals::to_signal(&matches.free[2])?
    } else {
        Signal::SIGTERM
    };
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(
        || format!("instance {} doesn't exist", id),
    )?;
    let mut f = File::open(INIT_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    if let Ok(init_pid) = result.parse::<i32>() {
        if signals::signal_process(init_pid, signal).is_err() {
            warn!("failed signal init process {}, may have exited", init_pid);
        }
    } else {
        warn!("invalid process pid: {}", result);
    }
    Ok(())
}

fn cmd_ps(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing ps");
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(
        || format!("instance {} doesn't exist", id),
    )?;
    let mut f = File::open(PROCESS_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    // TODO: return any other execed processes
    let mut pids = Vec::new();
    if let Ok(process_pid) = result.parse::<i32>() {
        pids.push(process_pid);
    } else {
        warn!("invalid process pid: {}", result);
    }
    println!(
        "{}",
        oci::serialize::to_string(&pids).chain_err(
            || "could not serialize pids",
        )?
    );
    Ok(())
}

fn cmd_delete(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing delete");
    let dir = instance_dir(id, state_dir);
    if chdir(&*dir).is_err() {
        debug!("instance {} doesn't exist", id);
        warn!("returning zero to work around docker bug");
        return Ok(());
    }
    if let Ok(mut f) = File::open(PROCESS_PID) {
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(process_pid) = result.parse::<i32>() {
            if signals::signal_process(process_pid, None).is_ok() {
                bail!("container process {} is still running", process_pid);
            }
        } else {
            warn!("invalid process pid: {}", result);
        }
    } else {
        debug!("process doesn't exist");
    }
    if let Ok(mut f) = File::open(INIT_PID) {
        debug!("killing init process");
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(ipid) = result.parse::<i32>() {
            if let Err(e) = signals::signal_process(ipid, Signal::SIGKILL) {
                let chain = || format!("failed to kill init {} ", ipid);
                if let Error(ErrorKind::Nix(n), _) = e {
                    if n.errno() == Errno::ESRCH {
                        debug!("init process is already dead");
                    } else {
                        Err(e).chain_err(chain)?;
                    }
                } else {
                    Err(e).chain_err(chain)?;
                }
            }
        } else {
            warn!("invalid init pid: {}", result);
        }
    } else {
        debug!("init process doesn't exist");
    }
    if let Ok(spec) = Spec::load(CONFIG) {
        let linux = spec.linux.as_ref().unwrap();
        let cpath = if linux.cgroups_path == "" {
            format!{"/{}", id}
        } else {
            linux.cgroups_path.clone()
        };
        debug!("removing cgroups");
        if let Err(Error(ErrorKind::Io(e), _)) = cgroups::remove(&cpath) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("failed to remove cgroup dir: {}", e);
            }
        }
        debug!("running poststop hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state_from_dir(id, state_dir)?;
            for h in &hooks.poststop {
                execute_hook(h, &st).chain_err(
                    || "failed to execute poststop hooks",
                )?;
            }
        }
    } else {
        debug!("config could not be loaded");
    }
    debug!("removing state dir {}", &dir);
    if let Err(e) = remove_dir_all(&dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let chain = || format!("removing state dir {} failed", &dir);
            Err(e).chain_err(chain)?;
        }
        bail!("State dir for {} disappeared", id);
    }

    Ok(())
}

fn cmd_run(id: &str, matches: &getopts::Matches) -> Result<()> {
    let bundle = if matches.free.len() >= 3 {
        &matches.free[2]
    } else {
        "."
    };
    chdir(&*bundle).chain_err(
        || format!("failed to chdir to {}", bundle),
    )?;
    let spec = Spec::load(CONFIG).chain_err(
        || format!("failed to load {}", CONFIG),
    )?;

    let child_pid = run_container(
        id,
        &spec.root.path,
        &spec,
        -1,
        !matches.opt_present("n"),
        matches.opt_present("o"),
        matches.opt_present("d"),
        -1,
    )?;
    info!("Container running with pid {}", child_pid);
    Ok(())
}

fn execute_hook(hook: &oci::Hook, state: &oci::State) -> Result<()> {
    debug!("executing hook {:?}", hook);
    let (rfd, wfd) = pipe2(O_CLOEXEC).chain_err(|| "failed to create pipe")?;
    match fork()? {
        ForkResult::Child => {
            close(rfd).chain_err(|| "could not close rfd")?;
            let (rstdin, wstdin) =
                pipe2(OFlag::empty()).chain_err(|| "failed to create pipe")?;
            // fork second child to execute hook
            match fork()? {
                ForkResult::Child => {
                    close(0).chain_err(|| "could not close stdin")?;
                    dup2(rstdin, 0).chain_err(|| "could not dup to stdin")?;
                    close(rstdin).chain_err(|| "could not close rstdin")?;
                    close(wstdin).chain_err(|| "could not close wstdin")?;
                    do_exec(&hook.path, &hook.args, &hook.env)?;
                }
                ForkResult::Parent { child } => {
                    close(rstdin).chain_err(|| "could not close rstdin")?;
                    unsafe {
                        // closes the file descriptor autmotaically
                        state.to_writer(File::from_raw_fd(wstdin)).chain_err(
                            || "could not write state",
                        )?;
                    }
                    let (exit_code, sig) = wait_for_child(child)?;
                    if let Some(signal) = sig {
                        // write signal to pipe.
                        let data: &[u8] = &[signal as u8];
                        write(wfd, data).chain_err(
                            || "failed to write signal hook",
                        )?;
                    }
                    close(wfd).chain_err(|| "could not close wfd")?;
                    std::process::exit(exit_code as i32);
                }
            }
        }
        ForkResult::Parent { child } => {
            // the wfd is only used by the child so close it
            close(wfd).chain_err(|| "could not close wfd")?;
            let mut timeout = -1 as i32;
            if let Some(t) = hook.timeout {
                timeout = t as i32 * 1000;
            }
            // a timeout will cause a failure and child will be killed on exit
            if let Some(sig) = wait_for_pipe_sig(rfd, timeout)? {
                let msg = format!{"hook exited with signal: {:?}", sig};
                return Err(ErrorKind::InvalidHook(msg).into());
            }
            let (exit_code, _) = wait_for_child(child)?;
            if exit_code != 0 {
                let msg = format!{"hook exited with exit code: {}", exit_code};
                return Err(ErrorKind::InvalidHook(msg).into());
            }
        }
    };
    Ok(())
}

fn run_container(
    id: &str,
    rootfs: &str,
    spec: &Spec,
    init_pid: i32,
    mut init: bool,
    mut init_only: bool,
    daemonize: bool,
    consolefd: RawFd,
) -> Result<(i32)> {
    if let Err(e) = prctl::set_dumpable(false) {
        bail!(format!("set dumpable returned {}", e));
    };

    // if selinux is disabled, set will fail so print a warning
    if !spec.process.selinux_label.is_empty() {
        if let Err(e) = selinux::setexeccon(&spec.process.selinux_label) {
            warn!(
                "could not set label to {}: {}",
                spec.process.selinux_label,
                e
            );
        };
    }

    if spec.linux.is_none() {
        let msg = "linux config is empty".to_string();
        return Err(ErrorKind::InvalidSpec(msg).into());
    }

    let linux = spec.linux.as_ref().unwrap();

    // initialize static variables before forking
    initialize(&DEFAULT_DEVICES);
    initialize(&NAMESPACES);
    cgroups::init();

    // colect namespaces
    let mut cf = CloneFlags::empty();
    let mut to_enter = Vec::new();
    let mut enter_pid = false;
    for ns in &linux.namespaces {
        let space = CloneFlags::from_bits_truncate(ns.typ as i32);
        if space == CLONE_NEWPID {
            enter_pid = true;
        }
        if ns.path.is_empty() {
            cf |= space;
        } else {
            let fd = open(&*ns.path, OFlag::empty(), Mode::empty()).chain_err(
                || {
                    format!("failed to open file for {:?}", space)
                },
            )?;
            to_enter.push((space, fd));
        }
    }
    if !enter_pid {
        init = false;
        init_only = false;
    }


    let cpath = if linux.cgroups_path == "" {
        format!{"/{}", id}
    } else {
        linux.cgroups_path.clone()
    };

    let mut bind_devices = false;
    let mut userns = false;
    let rlimits = &spec.process.rlimits;
    // fork for userns and cgroups
    if cf.contains(CLONE_NEWUSER) {
        bind_devices = true;
        userns = true;
    }

    if !daemonize {
        if let Err(e) = prctl::set_child_subreaper(true) {
            bail!(format!("set subreaper returned {}", e));
        };
    }
    let (child_pid, wfd) = fork_first(
        id,
        init_pid,
        enter_pid,
        init_only,
        daemonize,
        userns,
        linux,
        rlimits,
        &cpath,
        spec,
    )?;

    // parent returns child pid and exits
    if child_pid != -1 {
        return Ok(child_pid);
    }

    let mut mount_fd = -1;
    // enter path namespaces
    for &(space, fd) in &to_enter {
        if space == CLONE_NEWNS {
            // enter mount ns last
            mount_fd = fd;
            continue;
        }
        setns(fd, space).chain_err(
            || format!("failed to enter {:?}", space),
        )?;
        close(fd)?;
        if space == CLONE_NEWUSER {
            setid(0, 0).chain_err(|| "failed to setid")?;
            bind_devices = true;
        }
    }

    // TODO: handle systemd-style cgroup_path
    if !cpath.starts_with('/') {
        let msg = "cgroup path must be absolute".to_string();
        return Err(ErrorKind::InvalidSpec(msg).into());
    }

    // unshare other ns
    let chain = || format!("failed to unshare {:?}", cf);
    unshare(cf & !CLONE_NEWUSER).chain_err(chain)?;


    if enter_pid {
        fork_enter_pid(init, daemonize)?;
    };

    if cf.contains(CLONE_NEWUTS) {
        sethostname(&spec.hostname)?;
    }

    // NOTE: if we are running without a supplied console, then
    //       stdout and stderr will not be properly passed to
    //       docker since the start command has different stdout
    //       than the init command. In order to make this work
    //       we would need init to make a pseudoterminal and copy
    //       data back and forth, or pass the stdio file discriptors
    //       over a socket of some sort.
    if consolefd != -1 {
        setsid()?;
        if unsafe { libc::ioctl(consolefd, libc::TIOCSCTTY) } < 0 {
            warn!("could not TIOCSCTTY");
        };
        dup2(consolefd, 0).chain_err(
            || "could not dup tty to stdin",
        )?;
        dup2(consolefd, 1).chain_err(
            || "could not dup tty to stdout",
        )?;
        dup2(consolefd, 2).chain_err(
            || "could not dup tty to stderr",
        )?;

    // NOTE: we may need to fix up the mount of /dev/console
    } else if daemonize && !init_only {
        close(0).chain_err(|| "could not close stdin")?;
        close(1).chain_err(|| "could not close stdout")?;
        close(2).chain_err(|| "could not close stderr")?;
    }

    if cf.contains(CLONE_NEWNS) {
        mounts::init_rootfs(spec, rootfs, &cpath, bind_devices)
            .chain_err(|| "failed to init rootfs")?;
    }

    if !init_only {
        // notify first parent that it can continue
        debug!("writing zero to pipe to trigger prestart");
        let data: &[u8] = &[0];
        write(wfd, data).chain_err(|| "failed to write zero")?;
    }

    if mount_fd != -1 {
        setns(mount_fd, CLONE_NEWNS).chain_err(|| {
            "failed to enter CLONE_NEWNS".to_string()
        })?;
        close(mount_fd)?;
    }

    if cf.contains(CLONE_NEWNS) {

        mounts::pivot_rootfs(&*rootfs).chain_err(
            || "failed to pivot rootfs",
        )?;

        // only set sysctls in newns
        for (key, value) in &linux.sysctl {
            set_sysctl(key, value)?;
        }

        // NOTE: apparently criu has problems if pointing to an fd outside
        //       the filesystem namespace.
        reopen_dev_null()?;


        mounts::finish_rootfs(spec).chain_err(
            || "failed to finish rootfs",
        )?;
    }

    // change to specified working directory
    if !spec.process.cwd.is_empty() {
        chdir(&*spec.process.cwd)?;
    }

    debug!("setting ids");

    // set uid/gid/groups
    setid(spec.process.user.uid, spec.process.user.gid)?;
    if !spec.process.user.additional_gids.is_empty() {
        setgroups(&spec.process.user.additional_gids)?;
    }

    // NOTE: if we want init to pass signals to other processes, we may want
    //       to hold on to cap kill until after the final fork.
    if spec.process.no_new_privileges {
        if let Err(e) = prctl::set_no_new_privileges(true) {
            bail!(format!("set no_new_privs returned {}", e));
        };
        // drop privileges
        capabilities::drop_privileges(&spec.process.capabilities)?;
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
    } else {
        // NOTE: if we have not set no new privilges, we must set up seccomp
        //       before capset, which will error if seccomp blocks it
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
        // drop privileges
        capabilities::drop_privileges(&spec.process.capabilities)?;
    }


    if init && !init_only {
        fork_final_child(wfd, daemonize)?;
    }
    // notify first parent that it can continue
    debug!("writing zero to pipe to trigger poststart");
    let data: &[u8] = &[0];
    write(wfd, data).chain_err(|| "failed to write zero")?;
    if init_only {
        do_init(wfd, daemonize)?;
    }
    // we nolonger need wfd, so close it
    close(wfd).chain_err(|| "could not close wfd")?;
    do_exec(&spec.process.args[0], &spec.process.args, &spec.process.env)?;
    Ok(-1)
}

fn fork_first(
    id: &str,
    init_pid: i32,
    enter_pid: bool,
    init_only: bool,
    daemonize: bool,
    userns: bool,
    linux: &Linux,
    rlimits: &[LinuxRlimit],
    cpath: &str,
    spec: &Spec,
) -> Result<(i32, RawFd)> {
    let ccond = Cond::new().chain_err(|| "failed to create cond")?;
    let pcond = Cond::new().chain_err(|| "failed to create cond")?;
    let (rfd, wfd) = pipe2(O_CLOEXEC).chain_err(|| "failed to create pipe")?;
    match fork()? {
        ForkResult::Child => {
            close(rfd).chain_err(|| "could not close rfd")?;
            set_name("rc-user")?;

            // set oom_score_adj
            if let Some(ref r) = linux.resources {
                if let Some(adj) = r.oom_score_adj {
                    let mut f = File::create("/proc/self/oom_score_adj")?;
                    f.write_all(adj.to_string().as_bytes())?;
                }
            }

            // set rlimits (before entering user ns)
            for rlimit in rlimits.iter() {
                setrlimit(rlimit.typ as i32, rlimit.soft, rlimit.hard)?;
            }

            if userns {
                unshare(CLONE_NEWUSER).chain_err(
                    || "failed to unshare user",
                )?;
            }
            ccond.notify().chain_err(|| "failed to notify parent")?;
            pcond.wait().chain_err(|| "failed to wait for parent")?;
            if userns {
                setid(0, 0).chain_err(|| "failed to setid")?;
            }
            // child continues on
        }
        ForkResult::Parent { child } => {
            close(wfd).chain_err(|| "could not close wfd")?;
            ccond.wait().chain_err(|| "failed to wait for child")?;
            if userns {
                // write uid/gid map
                write_mappings(
                    &format!("/proc/{}/uid_map", child),
                    &linux.uid_mappings,
                ).chain_err(|| "failed to write uid mappings")?;
                write_mappings(
                    &format!("/proc/{}/gid_map", child),
                    &linux.gid_mappings,
                ).chain_err(|| "failed to write gid mappings")?;
            }
            // setup cgroups
            let schild = child.to_string();
            cgroups::apply(&linux.resources, &schild, cpath)?;
            // notify child
            pcond.notify().chain_err(|| "failed to notify child")?;

            // NOTE: if we are entering pid, we wait for the next
            //       child to exit so we can adopt its grandchild
            if enter_pid {
                let (_, _) = wait_for_child(child)?;
            }
            let mut pid = -1;
            wait_for_pipe_zero(rfd, -1)?;
            // get the actual pid of the process from cgroup
            let procs = cgroups::get_procs("cpuset", cpath);
            for p in procs {
                if p != init_pid {
                    debug!("actual pid of child is {}", p);
                    pid = p;
                    break;
                }
            }
            if !init_only {
                debug!("running prestart hooks");
                if let Some(ref hooks) = spec.hooks {
                    let st = state(id, "running", init_pid, &spec.root.path);
                    for h in &hooks.prestart {
                        execute_hook(h, &st).chain_err(
                            || "failed to execute prestart hooks",
                        )?;
                    }
                }
                wait_for_pipe_zero(rfd, -1)?;
                debug!("running poststart hooks");
                if let Some(ref hooks) = spec.hooks {
                    let st = state(id, "running", init_pid, &spec.root.path);
                    for h in &hooks.poststart {
                        if let Err(e) = execute_hook(h, &st) {
                            warn!("failed to execute poststart hook: {}", e);
                        }
                    }
                }
            }
            if daemonize {
                debug!("first parent exiting for daemonization");
                return Ok((pid, wfd));
            }
            signals::pass_signals(pid)?;
            let sig = wait_for_pipe_sig(rfd, -1)?;
            let (exit_code, _) = wait_for_child(pid)?;
            cgroups::remove(cpath)?;
            exit(exit_code, sig)?;
        }
    };
    Ok((-1, wfd))
}

fn fork_enter_pid(init: bool, daemonize: bool) -> Result<()> {
    // do the first fork right away because we must fork before we can
    // mount proc. The child will be in the pid namespace.
    match fork()? {
        ForkResult::Child => {
            if init {
                set_name("rc-init")?;
            } else if daemonize {
                // NOTE: if we are daemonizing non-init, we need an additional
                //       fork to allow process to be reparented to init
                match fork()? {
                    ForkResult::Child => {
                        // child continues
                    }
                    ForkResult::Parent { .. } => {
                        debug!("third parent exiting for daemonization");
                        exit(0, None)?;
                    }
                }
            }
            // child continues
        }
        ForkResult::Parent { .. } => {
            debug!("second parent exiting");
            exit(0, None)?;
        }
    };
    Ok(())
}

fn fork_final_child(wfd: RawFd, daemonize: bool) -> Result<()> {
    // fork again so child becomes pid 2
    match fork()? {
        ForkResult::Child => {
            // child continues on
            Ok(())
        }
        ForkResult::Parent { .. } => {
            do_init(wfd, daemonize)?;
            Ok(())
        }
    }
}

fn do_init(wfd: RawFd, daemonize: bool) -> Result<()> {
    if daemonize {
        close(wfd).chain_err(|| "could not close wfd")?;
    }
    let s = SigSet::all();
    s.thread_block()?;
    loop {
        let signal = s.wait()?;
        if signal == Signal::SIGCHLD {
            debug!("got a sigchld");
            let mut sig = None;
            let code;
            match reap_children()? {
                WaitStatus::Exited(_, c) => code = c as i32,
                WaitStatus::Signaled(_, s, _) => {
                    sig = Some(s);
                    code = 128 + s as libc::c_int;
                }
                _ => continue,
            };
            if !daemonize {
                if let Some(s) = sig {
                    // raising from pid 1 doesn't work as you would
                    // expect, so write signal to pipe.
                    let data: &[u8] = &[s as u8];
                    write(wfd, data).chain_err(|| "failed to write signal")?;
                }
                close(wfd).chain_err(|| "could not close wfd")?;
            }
            debug!("all children terminated, exiting with {}", code);
            std::process::exit(code)

        }
        debug!("passing {:?} on to children", signal);
        if let Err(e) = signals::signal_process(-1, signal) {
            warn!("failed to signal children, {}", e);
        }
    }
}

fn do_exec(path: &str, args: &[String], env: &[String]) -> Result<()> {
    let p = CString::new(path.to_string()).unwrap();
    let a: Vec<CString> = args.iter()
        .map(|s| CString::new(s.to_string()).unwrap_or_default())
        .collect();
    let env: Vec<CString> = env.iter()
        .map(|s| CString::new(s.to_string()).unwrap_or_default())
        .collect();
    // execvp doesn't use env for the search path, so we set env manually
    clearenv()?;
    for e in &env {
        debug!("adding {:?} to env", e);
        putenv(e)?;
    }
    execvp(&p, &a).chain_err(|| "failed to exec")?;
    // should never reach here
    Ok(())
}

fn write_mappings(path: &str, maps: &[LinuxIDMapping]) -> Result<()> {
    let mut data = String::new();
    for m in maps {
        let val = format!("{} {} {}\n", m.container_id, m.host_id, m.size);
        data = data + &val;
    }
    if !data.is_empty() {
        let fd = open(path, O_WRONLY, Mode::empty())?;
        defer!(close(fd).unwrap());
        write(fd, data.as_bytes())?;
    }
    Ok(())
}

fn set_sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!{"/proc/sys/{}", key.replace(".", "/")};
    let fd = match open(&*path, O_RDWR, Mode::empty()) {
        Err(e) => {
            if e.errno() != Errno::ENOENT {
                let msg = format!("could not set sysctl {} to {}", key, value);
                Err(e).chain_err(|| msg)?;
            }
            warn!("could not set {} because it doesn't exist", key);
            return Ok(());
        }
        Ok(fd) => fd,
    };
    defer!(close(fd).unwrap());
    write(fd, value.as_bytes())?;
    Ok(())
}

fn reopen_dev_null() -> Result<()> {
    let null_fd = open("/dev/null", O_WRONLY, Mode::empty())?;
    let null_stat = fstat(null_fd)?;
    defer!(close(null_fd).unwrap());
    for fd in 0..3 {
        if let Ok(stat) = fstat(fd) {
            if stat.st_rdev == null_stat.st_rdev {
                if fd == 0 {
                    // close and reopen to get RDONLY
                    close(fd)?;
                    open("/dev/null", O_RDONLY, Mode::empty())?;

                } else {
                    // we already have wronly fd, so duplicate it
                    dup2(null_fd, fd)?;
                }
            }
        }
    }
    Ok(())
}

fn wait_for_pipe_vec(
    rfd: RawFd,
    timeout: i32,
    num: usize,
) -> Result<(Vec<u8>)> {
    let mut result = Vec::new();
    while result.len() < num {
        let mut pfds =
            &mut [PollFd::new(rfd, POLLIN | POLLHUP, EventFlags::empty())];
        match poll(pfds, timeout) {
            Err(e) => {
                if e.errno() != Errno::EINTR {
                    return Err(e).chain_err(|| "unable to poll rfd")?;
                }
                continue;
            }
            Ok(n) => {
                if n == 0 {
                    return Err(ErrorKind::Timeout(timeout).into());
                }
            }
        }
        let events = pfds[0].revents();
        if events.is_none() {
            // continue on no events
            continue;
        }
        if events.unwrap() == POLLNVAL {
            let msg = "file descriptor closed unexpectedly".to_string();
            return Err(ErrorKind::PipeClosed(msg).into());
        }
        if !events.unwrap().intersects(POLLIN | POLLHUP) {
            // continue on other events (should not happen)
            debug!("got a continue on other events {:?}", events);
            continue;
        }
        let data: &mut [u8] = &mut [0];
        let n = read(rfd, data).chain_err(|| "could not read from rfd")?;
        if n == 0 {
            // the wfd was closed so close our end
            close(rfd).chain_err(|| "could not close rfd")?;
            break;
        }
        result.extend(data.iter().cloned());
    }
    Ok(result)
}

fn wait_for_pipe_sig(rfd: RawFd, timeout: i32) -> Result<Option<Signal>> {
    let result = wait_for_pipe_vec(rfd, timeout, 1)?;
    if result.len() < 1 {
        return Ok(None);
    }
    let chain = || "invalid signal";
    let s = Signal::from_c_int(result[0] as i32).chain_err(chain)?;
    Ok(Some(s))
}

fn wait_for_pipe_zero(rfd: RawFd, timeout: i32) -> Result<()> {
    let result = wait_for_pipe_vec(rfd, timeout, 1)?;
    if result.len() < 1 {
        let msg = "file descriptor closed unexpectedly".to_string();
        return Err(ErrorKind::PipeClosed(msg).into());
    }
    if result[0] != 0 {
        let msg = format!{"got {} from pipe instead of 0", result[0]};
        return Err(ErrorKind::InvalidValue(msg).into());
    }
    Ok(())
}

fn wait_for_child(child: i32) -> Result<(i8, Option<Signal>)> {
    loop {
        // wait on all children, but only return if we match child.
        let result = match waitpid(-1, None) {
            Err(e) => {
                // ignore EINTR as it gets sent when we get a SIGCHLD
                if e.errno() == Errno::EINTR {
                    continue;
                }
                let msg = format!("could not waitpid on {}", child);
                return Err(e).chain_err(|| msg)?;
            }
            Ok(s) => s,
        };
        match result {
            WaitStatus::Exited(pid, code) => {
                if child != -1 && pid != child {
                    continue;
                }
                reap_children()?;
                return Ok((code, None));
            }
            WaitStatus::Signaled(pid, signal, _) => {
                if child != -1 && pid != child {
                    continue;
                }
                reap_children()?;
                return Ok((0, Some(signal)));
            }
            _ => {}
        };
    }
}

fn exit(exit_code: i8, sig: Option<Signal>) -> Result<()> {
    match sig {
        Some(signal) => {
            debug!("child exited with signal {:?}", signal);

            signals::raise_for_parent(signal)?;
            // wait for normal signal handler to deal with us
            loop {
                signals::wait_for_signal()?;
            }
        }
        None => {
            debug!("child exited with code {:?}", exit_code);
            std::process::exit(exit_code as i32);
        }
    }
}

fn reap_children() -> Result<(WaitStatus)> {
    let mut result = WaitStatus::Exited(0, 0);
    loop {
        match waitpid(-1, Some(WNOHANG)) {
            Err(e) => {
                if e.errno() != Errno::ECHILD {
                    return Err(e).chain_err(|| "could not waitpid")?;
                }
                // ECHILD means no processes are left
                break;
            }
            Ok(s) => {
                result = s;
                if result == WaitStatus::StillAlive {
                    break;
                }
            }
        }
    }
    Ok(result)
}

fn setid(uid: u32, gid: u32) -> Result<()> {
    // set uid/gid
    if let Err(e) = prctl::set_keep_capabilities(true) {
        bail!(format!("set keep capabilities returned {}", e));
    };
    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;
    // if we change from zero, we lose effective caps
    if uid != 0 {
        capabilities::reset_effective()?;
    }
    if let Err(e) = prctl::set_keep_capabilities(false) {
        bail!(format!("set keep capabilities returned {}", e));
    };
    Ok(())
}

#[cfg(feature = "nightly")]
fn set_name(name: &str) -> Result<()> {
    match prctl::set_name(name) {
        Err(i) => bail!(format!("set name returned {}", i)),
        Ok(_) => (),
    };
    unsafe {
        let init = std::ffi::CString::new(name).chain_err(
            || "invalid process name",
        )?;
        let len = std::ffi::CStr::from_ptr(*ARGV).to_bytes().len();
        // after fork, ARGV points to the thread's local
        // copy of arg0.
        libc::strncpy(*ARGV, init.as_ptr(), len);
        // no need to set the final character to 0 since
        // the initial string was already null-terminated.
    }
    Ok(())
}

#[cfg(not(feature = "nightly"))]
fn set_name(name: &str) -> Result<()> {
    if let Err(e) = prctl::set_name(name) {
        bail!(format!("set name returned {}", e));
    };
    Ok(())
}
