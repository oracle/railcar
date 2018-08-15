error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }
    foreign_links {
        Nix(::nix::Error);
        Io(::std::io::Error);
        Ffi(::std::ffi::NulError);
        Caps(::caps::errors::Error);
    }
    errors {
        InvalidSpec(t: String) {
            description("invalid spec")
            display("invalid spec: '{}'", t)
        }
        SeccompError(t: String) {
            description("seccomp error")
            display("seccomp error: '{}'", t)
        }
        Timeout(timeout: i32) {
            description("timeout")
            display("timeout after {} milliseconds", timeout)
        }
        PipeClosed(t: String) {
            description("pipe closed")
            display("pipe closed: '{}'", t)
        }
        InvalidValue(t: String) {
            description("invalid value")
            display("invalid value: '{}'", t)
        }
        InvalidHook(t: String) {
            description("invalid hook")
            display("invalid hook: '{}'", t)
        }
    }
}
