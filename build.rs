use std::process::Command;

fn main() {
    // static link the musl target
    if std::env::var("TARGET").unwrap() == "x86_64-unknown-linux-musl" {
        let mut cmd = Command::new("./build_seccomp.sh");
        let output = cmd.output().expect("cmd failed to start");
        if !output.status.success() {
            println!("failed to build libseccomp:\n{}\n{}",
                   &std::str::from_utf8(&output.stdout).unwrap(),
                   &std::str::from_utf8(&output.stderr).unwrap());
            std::process::exit(1);
        }

        let dir = "/home/vishvananda/libseccomp/src/.libs";
        println!("cargo:rustc-link-search=native={}", dir);
        println!("cargo:rustc-link-lib=static=seccomp");
    }
}

