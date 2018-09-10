#![allow(unknown_lints)]
#![recursion_limit = "1024"]
#![cfg_attr(feature = "nightly", feature(start))]
#![cfg_attr(feature = "nightly", feature(alloc_system))]
#[cfg(feature = "nightly")]
extern crate alloc_system;

extern crate caps;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
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
extern crate oci;
extern crate seccomp_sys;

mod capabilities;
mod cgroups;
mod errors;
mod logger;
mod mounts;
mod nix_ext;
mod seccomp;
mod selinux;
mod signals;
mod sync;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use errors::*;
use lazy_static::initialize;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::poll::{poll, EventFlags, PollFd};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::socket::{accept, bind, connect, listen, sendmsg, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType, UnixAddr};
use nix::sys::socket::{ControlMessage, MsgFlags};
use nix::sys::stat::{fstat, Mode};
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, getpid, sethostname, setresgid, setresuid};
use nix::unistd::{close, dup2, fork, pipe2, read, setsid, write, ForkResult};
use nix::unistd::{Gid, Pid, Uid};
use nix_ext::{clearenv, putenv, setgroups, setrlimit};
use oci::{Linux, LinuxIDMapping, LinuxRlimit, Spec};
use oci::{LinuxDevice, LinuxDeviceType};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{canonicalize, create_dir, create_dir_all, remove_dir_all, File};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::io::{FromRawFd, RawFd};
use std::result::Result as StdResult;
use sync::Cond;

lazy_static! {
    static ref DEFAULT_DEVICES: Vec<LinuxDevice> = {
        let mut v = Vec::new();
        v.push(LinuxDevice {
            path: "/dev/null".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 3,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/zero".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 5,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/full".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 7,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/tty".to_string(),
            typ: LinuxDeviceType::c,
            major: 5,
            minor: 0,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/urandom".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 9,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
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
        result.insert(CloneFlags::CLONE_NEWIPC, "ipc");
        result.insert(CloneFlags::CLONE_NEWUTS, "uts");
        result.insert(CloneFlags::CLONE_NEWNET, "net");
        result.insert(CloneFlags::CLONE_NEWPID, "pid");
        result.insert(CloneFlags::CLONE_NEWNS, "mnt");
        result.insert(CloneFlags::CLONE_NEWCGROUP, "cgroup");
        result.insert(CloneFlags::CLONE_NEWUSER, "user");
        result
    };
}

const CONFIG: &'static str = "config.json";
const INIT_PID: &'static str = "init.pid";
const PROCESS_PID: &'static str = "process.pid";
const TSOCKETFD: RawFd = 9;

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
    if let Err(ref e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        print_backtrace(e);
        ::std::process::exit(1);
    }
    ::std::process::exit(0);
}

#[allow(needless_pass_by_value)]
fn id_validator(val: String) -> StdResult<(), String> {
    if val.contains("..") || val.contains('/') {
        return Err(format!("id {} may cannot contain '..' or '/'", val));
    }
    Ok(())
}

fn run() -> Result<()> {
    let id_arg = Arg::with_name("id")
        .required(true)
        .takes_value(true)
        .validator(id_validator)
        .help("Unique identifier");
    let bundle_arg = Arg::with_name("bundle")
        .required(true)
        .default_value(".")
        .long("bundle")
        .short("b")
        .help("Directory containing config.json");
    let pid_arg = Arg::with_name("p")
        .takes_value(true)
        .long("pid-file")
        .short("p")
        .help("Additional location to write pid");
    let init_arg = Arg::with_name("n")
        .help("Do not create an init process")
        .long("no-init")
        .short("n");

    let matches = App::new("Railcar")
        .about("Railcar - run a container from an oci-runtime spec file")
        .setting(AppSettings::ColoredHelp)
        .author(crate_authors!("\n"))
        .setting(AppSettings::SubcommandRequired)
        .version(crate_version!())
        .arg(
            Arg::with_name("v")
                .multiple(true)
                .help("Sets the level of verbosity")
                .short("v"),
        )
        .arg(
            Arg::with_name("d")
                .help("Daemonize the process")
                .long("daemonize")
                .short("d"),
        )
        .arg(
            Arg::with_name("log")
                .help("Compatibility (ignored)")
                .long("log")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-format")
                .help("Compatibility (ignored)")
                .long("log-format")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("r")
                .default_value("/run/railcar")
                .help("Dir for state")
                .long("root")
                .short("r")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("run")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(&bundle_arg)
                .arg(&pid_arg)
                .arg(&init_arg)
                .about("Run a container"),
        )
        .subcommand(
            SubCommand::with_name("create")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(&bundle_arg)
                .arg(&pid_arg)
                .arg(&init_arg)
                // NOTE(vish): if no-trigger is specified, console
                //             and console-socket will be loaded
                //             by start instead of create, so
                //             no output will appear from the init
                //             process.
                .arg(
                    Arg::with_name("t")
                        .help("Double fork instead of trigger")
                        .long("no-trigger")
                        .short("t"),
                )
                .arg(
                    Arg::with_name("c")
                        .help("Console to use")
                        .long("console")
                        .short("c")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("console-socket")
                        .help("socket to pass master of console")
                        .long("console-socket")
                        .takes_value(true),
                )
                .about("Create a container (to be started later)"),
        )
        .subcommand(
            SubCommand::with_name("start")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .about("Start a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("state")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .about(
                    "Get the (json) state of a (previously created) container",
                ),
        )
        .subcommand(
            SubCommand::with_name("kill")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("a")
                        .help("Compatibility (ignored)")
                        .long("all")
                        .short("a"),
                )
                .arg(
                    Arg::with_name("signal")
                        .default_value("TERM")
                        .required(true)
                        .takes_value(true)
                        .help("Signal to send to container"),
                )
                .about("Signal a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("f")
                        .help("Kill process if still running")
                        .long("force")
                        .short("f"),
                )
                .about("Delete a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("ps")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("f")
                        .help("Compatibility (ignored)")
                        .long("format")
                        .short("f")
                        .takes_value(true),
                )
                .about("List processes in a (previously created) container"),
        )
        .get_matches_from(get_args());
    let level = match matches.occurrences_of("v") {
        0 => log::LevelFilter::Info, //default
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    let _ = log::set_logger(&logger::SIMPLE_LOGGER)
        .map(|()| log::set_max_level(level));

    // create empty log file to avoid warning
    let lpath = matches.value_of("log").unwrap_or_default();
    if lpath != "" {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(lpath)?;
    }

    let state_dir = matches.value_of("r").unwrap().to_string();
    debug!("ensuring railcar state dir {}", &state_dir);
    let chain = || format!("ensuring railcar state dir {} failed", &state_dir);
    create_dir_all(&state_dir).chain_err(chain)?;

    match matches.subcommand() {
        ("create", Some(create_matches)) => cmd_create(
            create_matches.value_of("id").unwrap(),
            &state_dir,
            create_matches,
        ),
        ("delete", Some(delete_matches)) => cmd_delete(
            delete_matches.value_of("id").unwrap(),
            &state_dir,
            delete_matches,
        ),
        ("kill", Some(kill_matches)) => cmd_kill(
            kill_matches.value_of("id").unwrap(),
            &state_dir,
            kill_matches,
        ),
        ("ps", Some(ps_matches)) => {
            cmd_ps(ps_matches.value_of("id").unwrap(), &state_dir)
        }
        ("run", Some(run_matches)) => {
            cmd_run(run_matches.value_of("id").unwrap(), run_matches)
        }
        ("start", Some(start_matches)) => {
            cmd_start(start_matches.value_of("id").unwrap(), &state_dir)
        }
        ("state", Some(state_matches)) => {
            cmd_state(state_matches.value_of("id").unwrap(), &state_dir)
        }
        // We should never reach here because clap already enforces this
        _ => bail!("command not recognized"),
    }
}

#[inline]
fn instance_dir(id: &str, state_dir: &str) -> String {
    format!("{}/{}", state_dir, id)
}

fn state(id: &str, status: &str, pid: Pid, bundle: &str) -> oci::State {
    oci::State {
        version: "0.2.0".to_string(),
        id: id.to_string(),
        status: status.to_string(),
        pid: pid.into(), // TODO implement serde ser/de for Pid/Gid/..
        bundle: bundle.to_string(),
        annotations: HashMap::new(),
    }
}

// must be in instance_dir
fn get_init_pid() -> Result<(Pid)> {
    let mut pid = Pid::from_raw(-1);
    if let Ok(mut f) = File::open(INIT_PID) {
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(process_pid) = result.parse::<i32>() {
            pid = Pid::from_raw(process_pid);
        }
    }
    Ok(pid)
}

fn state_from_dir(id: &str, state_dir: &str) -> Result<(oci::State)> {
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
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
                if signals::signal_process(Pid::from_raw(process_pid), None)
                    .is_err()
                {
                    status = "stopped";
                }
            } else {
                // not safe to log during state because shim combines
                // stdout and stderr
                // warn!("invalid process pid: {}", result);
            }
        } else {
            // not safe to log during state because shim combines
            // stdout and stderr
            // warn!("could not open process pid");
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

fn cmd_create(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
    debug!("Performing create");
    let bundle = matches.value_of("bundle").unwrap();
    chdir(&*bundle).chain_err(|| format!("failed to chdir to {}", bundle))?;
    let dir = instance_dir(id, state_dir);
    debug!("creating state dir {}", &dir);
    if let Err(e) = create_dir(&dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let chain = || format!("creating state dir {} failed", &dir);
            Err(e).chain_err(chain)?;
        }
        bail!("Container with id {} already exists", id);
    }
    if let Err(e) = finish_create(id, &dir, matches) {
        let _ = remove_dir_all(&dir);
        Err(e)
    } else {
        Ok(())
    }
}

fn load_console_sockets() -> Result<(RawFd, RawFd)> {
    let csocket = "console-socket";
    let mut csocketfd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    csocketfd =
        match connect(csocketfd, &SockAddr::Unix(UnixAddr::new(&*csocket)?)) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::ENOENT) {
                    let msg = format!("failed to open {}", csocket);
                    return Err(e).chain_err(|| msg)?;
                }
                -1
            }
            Ok(()) => csocketfd,
        };
    let console = "console";
    let consolefd =
        match open(&*console, OFlag::O_NOCTTY | OFlag::O_RDWR, Mode::empty()) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::ENOENT) {
                    let msg = format!("failed to open {}", console);
                    return Err(e).chain_err(|| msg)?;
                }
                -1
            }
            Ok(fd) => fd,
        };
    Ok((csocketfd, consolefd))
}

fn finish_create(id: &str, dir: &str, matches: &ArgMatches) -> Result<()> {
    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let rootfs = canonicalize(&spec.root.path)
        .chain_err(|| format!{"failed to find root path {}", &spec.root.path})?
        .to_string_lossy()
        .into_owned();

    chdir(&*dir).chain_err(|| format!("failed to chdir to {}", &dir))?;
    // NOTE: There are certain configs where we will not be able to create a
    //       console during start, so this could potentially create the
    //       console during init and pass to the process via sendmsg. This
    //       would also allow us to write debug data from the init process
    //       to the console and allow us to pass stdoutio from init to the
    //       process, fixing the lack of stdout collection if -t is not
    //       specified when using docker run.
    let csocket = matches.value_of("console-socket").unwrap_or_default();
    if csocket != "" {
        let lnk = format!("{}/console-socket", dir);
        symlink(&csocket, lnk)?;
    }
    // symlink the console
    let cons = matches.value_of("c").unwrap_or_default();
    if cons != "" {
        let lnk = format!("{}/console", dir);
        symlink(&cons, lnk)?;
    }
    let (csocketfd, consolefd, tsocketfd) = if !matches.is_present("t") {
        let tsocket = "trigger-socket";
        let tmpfd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;
        // NOTE(vish): we might overwrite fds 0, 1, 2 with the console
        //             so make sure tsocketfd is a high fd that won't
        //             get overwritten
        dup2(tmpfd, TSOCKETFD).chain_err(|| "could not dup tsocketfd")?;
        close(tmpfd).chain_err(|| "could not close tsocket tmpfd")?;
        let tsocketfd = TSOCKETFD;
        bind(tsocketfd, &SockAddr::Unix(UnixAddr::new(&*tsocket)?))?;
        let (csocketfd, consolefd) = load_console_sockets()?;
        (csocketfd, consolefd, tsocketfd)
    } else {
        (-1, -1, -1)
    };

    let pidfile = matches.value_of("p").unwrap_or_default();

    let child_pid = safe_run_container(
        id,
        &rootfs,
        &spec,
        Pid::from_raw(-1),
        true,
        true,
        true,
        csocketfd,
        consolefd,
        tsocketfd,
    )?;
    if child_pid != Pid::from_raw(-1) {
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
            mounts: Vec::new(),       // remove mounts
            hooks: spec.hooks,
            annotations: spec.annotations,
            linux: Some(updated_linux),
            solaris: spec.solaris,
            windows: spec.windows,
        };
        debug!("writing updated config");
        updated
            .save(CONFIG)
            .chain_err(|| format!("failed to save {}", CONFIG))?;
    }
    Ok(())
}

fn cmd_start(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing start");

    // we use instance dir for config written out by create
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;

    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let init_pid = get_init_pid()?;

    let tsocket = "trigger-socket";
    let mut tsocketfd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    tsocketfd =
        match connect(tsocketfd, &SockAddr::Unix(UnixAddr::new(&*tsocket)?)) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::ENOENT) {
                    let msg = format!("failed to open {}", tsocket);
                    return Err(e).chain_err(|| msg)?;
                }
                -1
            }
            Ok(()) => tsocketfd,
        };

    // if we are triggering just trigger and exit
    if tsocketfd != -1 {
        debug!("running prestart hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state(id, "running", init_pid, &spec.root.path);
            for h in &hooks.prestart {
                execute_hook(h, &st)
                    .chain_err(|| "failed to execute prestart hooks")?;
            }
        }
        let linux = spec.linux.as_ref().unwrap();
        let cpath = if linux.cgroups_path == "" {
            format!{"/{}", id}
        } else {
            linux.cgroups_path.clone()
        };
        // get the actual pid of the process from cgroup
        let mut child_pid = Pid::from_raw(-1);
        let procs = cgroups::get_procs("cpuset", &cpath);
        for p in procs {
            if p != init_pid {
                debug!("actual pid of child is {}", p);
                child_pid = p;
                break;
            }
        }
        let mut f = File::create(PROCESS_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
        debug!("running poststart hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state(id, "running", init_pid, &spec.root.path);
            for h in &hooks.poststart {
                if let Err(e) = execute_hook(h, &st) {
                    warn!("failed to execute poststart hook: {}", e);
                }
            }
        }
        debug!("writing zero to trigger socket to start exec");
        let data: &[u8] = &[0];
        write(tsocketfd, data).chain_err(|| "failed to write zero")?;
        return Ok(());
    }

    let (csocketfd, consolefd) = load_console_sockets()?;

    let child_pid = safe_run_container(
        id,
        &spec.root.path,
        &spec,
        init_pid,
        false,
        false,
        true,
        csocketfd,
        consolefd,
        -1,
    )?;
    if child_pid != Pid::from_raw(-1) {
        debug!("writing process {} pid file", child_pid);
        let mut f = File::create(PROCESS_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
    }
    Ok(())
}

fn cmd_kill(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
    debug!("Performing kill");
    let signal = signals::to_signal(matches.value_of("signal").unwrap())
        .unwrap_or(Signal::SIGTERM);
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
    let mut f = File::open(INIT_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    if let Ok(init_pid) = result.parse::<i32>() {
        if signals::signal_process(Pid::from_raw(init_pid), signal).is_err() {
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
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
    let mut f = File::open(PROCESS_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    // TODO: return any other execed processes
    let mut pids = Vec::new();
    if let Ok(process_pid) = result.parse::<i32>() {
        pids.push(Pid::from_raw(process_pid));
    } else {
        warn!("invalid process pid: {}", result);
    }
    let pids = pids
        .into_iter()
        .map(|pid: Pid| -> i32 { pid.into() })
        .collect::<Vec<i32>>();
    println!(
        "{}",
        oci::serialize::to_string(&pids)
            .chain_err(|| "could not serialize pids")?
    );
    Ok(())
}

fn cmd_delete(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
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
            let process_pid = Pid::from_raw(process_pid);

            if signals::signal_process(process_pid, None).is_ok() {
                if matches.is_present("f") {
                    if let Err(e) =
                        signals::signal_process(process_pid, Signal::SIGKILL)
                    {
                        let chain = || {
                            format!("failed to kill process {} ", process_pid)
                        };
                        if let Error(ErrorKind::Nix(nixerr), _) = e {
                            if nixerr == ::nix::Error::Sys(Errno::ESRCH) {
                                debug!("container process is already dead");
                            } else {
                                Err(e).chain_err(chain)?;
                            }
                        } else {
                            Err(e).chain_err(chain)?;
                        }
                    }
                } else {
                    bail!("container process {} is still running", process_pid)
                }
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
            if let Err(e) =
                signals::signal_process(Pid::from_raw(ipid), Signal::SIGKILL)
            {
                let chain = || format!("failed to kill init {} ", ipid);
                if let Error(ErrorKind::Nix(nixerr), _) = e {
                    if let ::nix::Error::Sys(errno) = nixerr {
                        if errno == Errno::ESRCH {
                            debug!("init process is already dead");
                        }
                        Err(e).chain_err(chain)?;
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
                execute_hook(h, &st)
                    .chain_err(|| "failed to execute poststop hooks")?;
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

fn cmd_run(id: &str, matches: &ArgMatches) -> Result<()> {
    let bundle = matches.value_of("bundle").unwrap();
    chdir(&*bundle).chain_err(|| format!("failed to chdir to {}", bundle))?;
    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let child_pid = safe_run_container(
        id,
        &spec.root.path,
        &spec,
        Pid::from_raw(-1),
        !matches.is_present("n"),
        false,
        matches.is_present("d"),
        -1,
        -1,
        -1,
    )?;
    info!("Container running with pid {}", child_pid);
    Ok(())
}

fn execute_hook(hook: &oci::Hook, state: &oci::State) -> Result<()> {
    debug!("executing hook {:?}", hook);
    let (rfd, wfd) =
        pipe2(OFlag::O_CLOEXEC).chain_err(|| "failed to create pipe")?;
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
                        state
                            .to_writer(File::from_raw_fd(wstdin))
                            .chain_err(|| "could not write state")?;
                    }
                    let (exit_code, sig) = wait_for_child(child)?;
                    if let Some(signal) = sig {
                        // write signal to pipe.
                        let data: &[u8] = &[signal as u8];
                        write(wfd, data)
                            .chain_err(|| "failed to write signal hook")?;
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

fn safe_run_container(
    id: &str,
    rootfs: &str,
    spec: &Spec,
    init_pid: Pid,
    init: bool,
    init_only: bool,
    daemonize: bool,
    csocketfd: RawFd,
    consolefd: RawFd,
    tsocketfd: RawFd,
) -> Result<Pid> {
    let pid = getpid();
    match run_container(
        id, rootfs, spec, init_pid, init, init_only, daemonize, csocketfd,
        consolefd, tsocketfd,
    ) {
        Err(e) => {
            // if we are the top level thread, kill all children
            if pid == getpid() {
                signals::signal_children(Signal::SIGTERM).unwrap();
            }
            Err(e)
        }
        Ok(child_pid) => Ok(child_pid),
    }
}

fn run_container(
    id: &str,
    rootfs: &str,
    spec: &Spec,
    init_pid: Pid,
    mut init: bool,
    mut init_only: bool,
    daemonize: bool,
    csocketfd: RawFd,
    mut consolefd: RawFd,
    tsocketfd: RawFd,
) -> Result<Pid> {
    if let Err(e) = prctl::set_dumpable(false) {
        bail!(format!("set dumpable returned {}", e));
    };

    // if selinux is disabled, set will fail so print a warning
    if !spec.process.selinux_label.is_empty() {
        if let Err(e) = selinux::setexeccon(&spec.process.selinux_label) {
            warn!(
                "could not set label to {}: {}",
                spec.process.selinux_label, e
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

    // collect namespaces
    let mut cf = CloneFlags::empty();
    let mut to_enter = Vec::new();
    let mut enter_pid = false;
    for ns in &linux.namespaces {
        let space = CloneFlags::from_bits_truncate(ns.typ as i32);
        if space == CloneFlags::CLONE_NEWPID {
            enter_pid = true;
        }
        if ns.path.is_empty() {
            cf |= space;
        } else {
            let fd = open(&*ns.path, OFlag::empty(), Mode::empty())
                .chain_err(|| format!("failed to open file for {:?}", space))?;
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
    if cf.contains(CloneFlags::CLONE_NEWUSER) {
        bind_devices = true;
        userns = true;
    }

    if !daemonize {
        if let Err(e) = prctl::set_child_subreaper(true) {
            bail!(format!("set subreaper returned {}", e));
        };
    }
    let (child_pid, wfd) = fork_first(
        id, init_pid, enter_pid, init_only, daemonize, userns, linux, rlimits,
        &cpath, spec,
    )?;

    // parent returns child pid and exits
    if child_pid != Pid::from_raw(-1) {
        return Ok(child_pid);
    }

    let mut mount_fd = -1;
    // enter path namespaces
    for &(space, fd) in &to_enter {
        if space == CloneFlags::CLONE_NEWNS {
            // enter mount ns last
            mount_fd = fd;
            continue;
        }
        setns(fd, space).chain_err(|| format!("failed to enter {:?}", space))?;
        close(fd)?;
        if space == CloneFlags::CLONE_NEWUSER {
            setid(Uid::from_raw(0), Gid::from_raw(0))
                .chain_err(|| "failed to setid")?;
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
    unshare(cf & !CloneFlags::CLONE_NEWUSER).chain_err(chain)?;

    if enter_pid {
        fork_enter_pid(init, daemonize)?;
    };

    if cf.contains(CloneFlags::CLONE_NEWUTS) {
        sethostname(&spec.hostname)?;
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
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
        setns(mount_fd, CloneFlags::CLONE_NEWNS).chain_err(|| {
            "failed to enter CloneFlags::CLONE_NEWNS".to_string()
        })?;
        close(mount_fd)?;
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::pivot_rootfs(&*rootfs).chain_err(|| "failed to pivot rootfs")?;

        // only set sysctls in newns
        for (key, value) in &linux.sysctl {
            set_sysctl(key, value)?;
        }

        // NOTE: apparently criu has problems if pointing to an fd outside
        //       the filesystem namespace.
        reopen_dev_null()?;
    }

    if csocketfd != -1 {
        let mut slave: libc::c_int = unsafe { std::mem::uninitialized() };
        let mut master: libc::c_int = unsafe { std::mem::uninitialized() };
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        Errno::result(ret).chain_err(|| "could not openpty")?;
        defer!(close(master).unwrap());
        let data: &[u8] = b"/dev/ptmx";
        let iov = [nix::sys::uio::IoVec::from_slice(data)];
        //let fds = [master.as_raw_fd()];
        let fds = [master];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg(csocketfd, &iov, &[cmsg], MsgFlags::empty(), None)?;
        consolefd = slave;
        close(csocketfd).chain_err(|| "could not close csocketfd")?;
    }
    if consolefd != -1 {
        setsid()?;
        if unsafe { libc::ioctl(consolefd, libc::TIOCSCTTY) } < 0 {
            warn!("could not TIOCSCTTY");
        };
        dup2(consolefd, 0).chain_err(|| "could not dup tty to stdin")?;
        dup2(consolefd, 1).chain_err(|| "could not dup tty to stdout")?;
        dup2(consolefd, 2).chain_err(|| "could not dup tty to stderr")?;

        if consolefd > 2 {
            close(consolefd).chain_err(|| "could not close consolefd")?;
        }

        // NOTE: we may need to fix up the mount of /dev/console
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::finish_rootfs(spec).chain_err(|| "failed to finish rootfs")?;
    }

    // change to specified working directory
    if !spec.process.cwd.is_empty() {
        chdir(&*spec.process.cwd)?;
    }

    debug!("setting ids");

    // set uid/gid/groups
    let uid = Uid::from_raw(spec.process.user.uid);
    let gid = Gid::from_raw(spec.process.user.gid);
    setid(uid, gid)?;
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
        if let Some(ref c) = spec.process.capabilities {
            capabilities::drop_privileges(c)?;
        }
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
    } else {
        // NOTE: if we have not set no new priviliges, we must set up seccomp
        //       before capset, which will error if seccomp blocks it
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
        // drop privileges
        if let Some(ref c) = spec.process.capabilities {
            capabilities::drop_privileges(c)?;
        }
    }

    // notify first parent that it can continue
    debug!("writing zero to pipe to trigger poststart");
    let data: &[u8] = &[0];
    write(wfd, data).chain_err(|| "failed to write zero")?;

    if init {
        if init_only && tsocketfd == -1 {
            do_init(wfd, daemonize)?;
        } else {
            fork_final_child(wfd, tsocketfd, daemonize)?;
        }
    }

    // we nolonger need wfd, so close it
    close(wfd).chain_err(|| "could not close wfd")?;

    // wait for trigger
    if tsocketfd != -1 {
        listen(tsocketfd, 1)?;
        let fd = accept(tsocketfd)?;
        wait_for_pipe_zero(fd, -1)?;
        close(fd).chain_err(|| "could not close accept fd")?;
        close(tsocketfd).chain_err(|| "could not close trigger fd")?;
    }

    do_exec(&spec.process.args[0], &spec.process.args, &spec.process.env)?;
    Ok(Pid::from_raw(-1))
}

fn fork_first(
    id: &str,
    init_pid: Pid,
    enter_pid: bool,
    init_only: bool,
    daemonize: bool,
    userns: bool,
    linux: &Linux,
    rlimits: &[LinuxRlimit],
    cpath: &str,
    spec: &Spec,
) -> Result<(Pid, RawFd)> {
    let ccond = Cond::new().chain_err(|| "failed to create cond")?;
    let pcond = Cond::new().chain_err(|| "failed to create cond")?;
    let (rfd, wfd) =
        pipe2(OFlag::O_CLOEXEC).chain_err(|| "failed to create pipe")?;
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
                unshare(CloneFlags::CLONE_NEWUSER)
                    .chain_err(|| "failed to unshare user")?;
            }
            ccond.notify().chain_err(|| "failed to notify parent")?;
            pcond.wait().chain_err(|| "failed to wait for parent")?;
            if userns {
                setid(Uid::from_raw(0), Gid::from_raw(0))
                    .chain_err(|| "failed to setid")?;
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
            let mut pid = Pid::from_raw(-1);
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
                        execute_hook(h, &st)
                            .chain_err(|| "failed to execute prestart hooks")?;
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
            exit(exit_code as i8, sig)?;
        }
    };
    Ok((Pid::from_raw(-1), wfd))
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

fn fork_final_child(wfd: RawFd, tfd: RawFd, daemonize: bool) -> Result<()> {
    // fork again so child becomes pid 2
    match fork()? {
        ForkResult::Child => {
            // child continues on
            Ok(())
        }
        ForkResult::Parent { .. } => {
            if tfd != -1 {
                close(tfd).chain_err(|| "could not close trigger fd")?;
            }
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
        if let Err(e) = signals::signal_process(Pid::from_raw(-1), signal) {
            warn!("failed to signal children, {}", e);
        }
    }
}

fn do_exec(path: &str, args: &[String], env: &[String]) -> Result<()> {
    let p = CString::new(path.to_string()).unwrap();
    let a: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.to_string()).unwrap_or_default())
        .collect();
    let env: Vec<CString> = env
        .iter()
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
        let fd = open(path, OFlag::O_WRONLY, Mode::empty())?;
        defer!(close(fd).unwrap());
        write(fd, data.as_bytes())?;
    }
    Ok(())
}

fn set_sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!{"/proc/sys/{}", key.replace(".", "/")};
    let fd = match open(&*path, OFlag::O_RDWR, Mode::empty()) {
        Err(::nix::Error::Sys(errno)) => {
            if errno != Errno::ENOENT {
                let msg = format!("could not set sysctl {} to {}", key, value);
                Err(::nix::Error::Sys(errno)).chain_err(|| msg)?;
            }
            warn!("could not set {} because it doesn't exist", key);
            return Ok(());
        }
        Err(e) => Err(e)?,
        Ok(fd) => fd,
    };
    defer!(close(fd).unwrap());
    write(fd, value.as_bytes())?;
    Ok(())
}

fn reopen_dev_null() -> Result<()> {
    let null_fd = open("/dev/null", OFlag::O_WRONLY, Mode::empty())?;
    let null_stat = fstat(null_fd)?;
    defer!(close(null_fd).unwrap());
    for fd in 0..3 {
        if let Ok(stat) = fstat(fd) {
            if stat.st_rdev == null_stat.st_rdev {
                if fd == 0 {
                    // close and reopen to get RDONLY
                    close(fd)?;
                    open("/dev/null", OFlag::O_RDONLY, Mode::empty())?;
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
        let pfds =
            &mut [PollFd::new(rfd, EventFlags::POLLIN | EventFlags::POLLHUP)];
        match poll(pfds, timeout) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::EINTR) {
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
        if events.unwrap() == EventFlags::POLLNVAL {
            let msg = "file descriptor closed unexpectedly".to_string();
            return Err(ErrorKind::PipeClosed(msg).into());
        }
        if !events
            .unwrap()
            .intersects(EventFlags::POLLIN | EventFlags::POLLHUP)
        {
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

fn wait_for_child(child: Pid) -> Result<(i32, Option<Signal>)> {
    loop {
        // wait on all children, but only return if we match child.
        let result = match waitpid(Pid::from_raw(-1), None) {
            Err(::nix::Error::Sys(errno)) => {
                // ignore EINTR as it gets sent when we get a SIGCHLD
                if errno == Errno::EINTR {
                    continue;
                }
                let msg = format!("could not waitpid on {}", child);
                return Err(::nix::Error::Sys(errno)).chain_err(|| msg)?;
            }
            Err(e) => {
                return Err(e)?;
            }
            Ok(s) => s,
        };
        match result {
            WaitStatus::Exited(pid, code) => {
                if child != Pid::from_raw(-1) && pid != child {
                    continue;
                }
                reap_children()?;
                return Ok((code as i32, None));
            }
            WaitStatus::Signaled(pid, signal, _) => {
                if child != Pid::from_raw(-1) && pid != child {
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
    let mut result = WaitStatus::Exited(Pid::from_raw(0), 0);
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::ECHILD) {
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

fn setid(uid: Uid, gid: Gid) -> Result<()> {
    // set uid/gid
    if let Err(e) = prctl::set_keep_capabilities(true) {
        bail!(format!("set keep capabilities returned {}", e));
    };
    {
        setresgid(gid, gid, gid)?;
    }
    {
        setresuid(uid, uid, uid)?;
    }
    // if we change from zero, we lose effective caps
    if uid != Uid::from_raw(0) {
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
        let init =
            std::ffi::CString::new(name).chain_err(|| "invalid process name")?;
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
