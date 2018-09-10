use std::env;
use std::fs::File;
use std::io::Read;
use std::process::Command;

fn main() {
    // static link the musl target
    if env::var("TARGET").unwrap() == "x86_64-unknown-linux-musl" {
        let mut cmd = Command::new("./build_seccomp.sh");
        let output = cmd.output().expect("cmd failed to start");
        if !output.status.success() {
            println!(
                "failed to build libseccomp:\n{}\n{}",
                &std::str::from_utf8(&output.stdout).unwrap(),
                &std::str::from_utf8(&output.stderr).unwrap()
            );
            let mut f = File::open("libseccomp/config.log").unwrap();
            let mut result = String::new();
            f.read_to_string(&mut result).unwrap();
            println!{"{}", &result};
            std::process::exit(1);
        }

        let pwd = std::env::var("PWD").unwrap();
        let dir = format!("{}/libseccomp/src/.libs", pwd);
        println!("cargo:rustc-link-search=native={}", dir);
        println!("cargo:rustc-link-lib=static=seccomp");
    }
}
