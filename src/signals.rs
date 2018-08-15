use errors::*;
use libc::c_int;
use nix::sys::signal::{kill, raise, sigaction};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::Pid;

pub fn pass_signals(child_pid: Pid) -> Result<()> {
    unsafe {
        CHILD_PID = Some(child_pid);
        set_handler(SigHandler::Handler(child_handler))?;
    }
    Ok(())
}

// NOTE: signal handlers need to know which child to pass
// a signal to. We store the child's pid in a global variable.
// The child pid is only set once prior to setting up the
// signal handler, so it should be safe to access it from the
// signal handler.
static mut CHILD_PID: Option<Pid> = None;

extern "C" fn child_handler(signo: c_int) {
    unsafe {
        let _ = kill(
            CHILD_PID.unwrap_or(Pid::from_raw(0)),
            Signal::from_c_int(signo).unwrap(),
        );
    }
}

unsafe fn set_handler(handler: SigHandler) -> Result<()> {
    let a = SigAction::new(handler, SaFlags::empty(), SigSet::all());
    sigaction(Signal::SIGTERM, &a).chain_err(|| "failed to sigaction")?;
    sigaction(Signal::SIGQUIT, &a).chain_err(|| "failed to sigaction")?;
    sigaction(Signal::SIGINT, &a).chain_err(|| "failed to sigaction")?;
    sigaction(Signal::SIGHUP, &a).chain_err(|| "failed to sigaction")?;
    sigaction(Signal::SIGUSR1, &a).chain_err(|| "failed to sigaction")?;
    sigaction(Signal::SIGUSR2, &a).chain_err(|| "failed to sigaction")?;
    Ok(())
}

pub fn signal_children(signal: Signal) -> Result<()> {
    // don't signal this thread
    let mut s = SigSet::empty();
    s.add(signal);
    s.thread_block()?;
    kill(Pid::from_raw(0), signal)?;
    Ok(())
}

pub fn to_signal(signal: &str) -> Result<Signal> {
    Ok(match signal {
        "1" | "HUP" | "SIGHUP" => Signal::SIGHUP,
        "2" | "INT" | "SIGINT" => Signal::SIGINT,
        "3" | "QUIT" | "SIGQUIT" => Signal::SIGQUIT,
        "4" | "ILL" | "SIGILL" => Signal::SIGILL,
        "5" | "BUS" | "SIGBUS" => Signal::SIGBUS,
        "6" | "ABRT" | "IOT" | "SIGABRT" | "SIGIOT" => Signal::SIGABRT,
        "7" | "TRAP" | "SIGTRAP" => Signal::SIGTRAP,
        "8" | "FPE" | "SIGFPE" => Signal::SIGFPE,
        "9" | "KILL" | "SIGKILL" => Signal::SIGKILL,
        "10" | "USR1" | "SIGUSR1" => Signal::SIGUSR1,
        "11" | "SEGV" | "SIGSEGV" => Signal::SIGSEGV,
        "12" | "USR2" | "SIGUSR2" => Signal::SIGUSR2,
        "13" | "PIPE" | "SIGPIPE" => Signal::SIGPIPE,
        "14" | "ALRM" | "SIGALRM" => Signal::SIGALRM,
        "15" | "TERM" | "SIGTERM" => Signal::SIGTERM,
        "16" | "STKFLT" | "SIGSTKFLT" => Signal::SIGSTKFLT,
        "17" | "CHLD" | "SIGCHLD" => Signal::SIGCHLD,
        "18" | "CONT" | "SIGCONT" => Signal::SIGCONT,
        "19" | "STOP" | "SIGSTOP" => Signal::SIGSTOP,
        "20" | "TSTP" | "SIGTSTP" => Signal::SIGTSTP,
        "21" | "TTIN" | "SIGTTIN" => Signal::SIGTTIN,
        "22" | "TTOU" | "SIGTTOU" => Signal::SIGTTOU,
        "23" | "URG" | "SIGURG" => Signal::SIGURG,
        "24" | "XCPU" | "SIGXCPU" => Signal::SIGXCPU,
        "25" | "XFSZ" | "SIGXFSZ" => Signal::SIGXFSZ,
        "26" | "VTALRM" | "SIGVTALRM" => Signal::SIGVTALRM,
        "27" | "PROF" | "SIGPROF" => Signal::SIGPROF,
        "28" | "WINCH" | "SIGWINCH" => Signal::SIGWINCH,
        "29" | "IO" | "SIGIO" => Signal::SIGIO,
        "30" | "PWR" | "SIGPWR" => Signal::SIGPWR,
        "31" | "SYS" | "SIGSYS" => Signal::SIGSYS,
        _ => bail!{"{} is not a valid signal", signal},
    })
}

pub fn signal_process<T: Into<Option<Signal>>>(
    pid: Pid,
    signal: T,
) -> Result<()> {
    kill(pid, signal)?;
    Ok(())
}

pub fn raise_for_parent(signal: Signal) -> Result<()> {
    // reset the sigaction for the signal
    if signal != Signal::SIGKILL && signal != Signal::SIGSTOP {
        let a =
            SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::all());
        unsafe {
            sigaction(signal, &a).chain_err(|| "failed to sigaction")?;
        }
    }
    // make sure the signal is unblocked
    let mut s = SigSet::empty();
    s.add(signal);
    s.thread_unblock().chain_err(|| "failed to unblock signal")?;
    // raise the signal
    raise(signal).chain_err(|| format!("failed to raise signal {:?}", signal))?;
    Ok(())
}

pub fn wait_for_signal() -> Result<Signal> {
    let s = SigSet::all();
    s.thread_block()?;
    let result = s.wait()?;
    s.thread_unblock()?;
    Ok(result)
}
