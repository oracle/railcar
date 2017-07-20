use errors::*;
use oci::{Arch, LinuxSeccomp, LinuxSeccompOperator};
use seccomp_sys::*;

fn to_arch(arch: Arch) -> scmp_arch {
    unsafe { ::std::mem::transmute(arch) }
}

fn to_cmp(cmp: LinuxSeccompOperator) -> scmp_compare {
    unsafe { ::std::mem::transmute(cmp) }
}

fn syscall_resolve_name(name: &str) -> ::Result<i32> {
    let s = ::std::ffi::CString::new(name)?;
    let id = unsafe { seccomp_syscall_resolve_name(s.as_ptr()) };
    if id == __NR_SCMP_ERROR {
        let msg = format!("could not resolve {}", name);
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(id)
    }
}

fn init(act: u32) -> Result<*mut scmp_filter_ctx> {
    let filter_ctx = unsafe { seccomp_init(act) };
    if filter_ctx.is_null() {
        let msg = "initialization failed".to_string();
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(filter_ctx)
    }
}

fn arch_add(ctx: *mut scmp_filter_ctx, arch: scmp_arch) -> ::Result<i32> {
    let id = unsafe { seccomp_arch_add(ctx, arch as u32) };
    if id == __NR_SCMP_ERROR {
        let msg = format!("could not add arch {:?}", arch);
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(id)
    }
}

fn rule_add(
    ctx: *mut scmp_filter_ctx,
    act: u32,
    id: i32,
    cmps: &[scmp_arg_cmp],
) -> Result<()> {
    let res = unsafe {
        let ptr = if cmps.is_empty() {
            ::std::ptr::null()
        } else {
            cmps.as_ptr()
        };
        seccomp_rule_add_array(ctx, act, id, cmps.len() as u32, ptr)
    };
    if res != 0 {
        let msg = format!("failed to add rule for {}", id);
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(())
    }
}

fn attr_set(
    ctx: *mut scmp_filter_ctx,
    attr: scmp_filter_attr,
    value: u32,
) -> Result<()> {
    let res = unsafe { seccomp_attr_set(ctx, attr, value) };
    if res != 0 {
        let msg = "failed to set_attr".to_string();
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(())
    }
}

fn load(ctx: *mut scmp_filter_ctx) -> Result<()> {
    let res = unsafe { seccomp_load(ctx) };
    if res != 0 {
        let msg = "failed to load filter".to_string();
        Err(ErrorKind::SeccompError(msg).into())
    } else {
        Ok(())
    }
}

pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> ::Result<()> {
    let ctx = init(seccomp.default_action as u32)?;
    // set control NoNewPrivs to false, as we deal with it separately
    attr_set(ctx, scmp_filter_attr::SCMP_FLTATR_CTL_NNP, false as u32)?;
    // set up architectures
    for arch in &seccomp.architectures {
        arch_add(ctx, to_arch(*arch))?;
    }
    // add actions for syscalls
    for syscall in &seccomp.syscalls {
        let mut names = syscall.names.clone();
        if names.is_empty() {
            names.push(syscall.name.clone())
        };
        for name in names {
            let id = match syscall_resolve_name(&name) {
                Ok(result) => result,
                Err(e) => {
                    info!("Skipping unknown syscall: {}", e);
                    continue;
                }
            };
            let mut cmps = Vec::new();
            for arg in &syscall.args {
                cmps.push(scmp_arg_cmp {
                    arg: arg.index as u32,
                    op: to_cmp(arg.op),
                    datum_a: arg.value as scmp_datum_t,
                    datum_b: arg.value_two as scmp_datum_t,
                });
            }

            rule_add(ctx, syscall.action as u32, id, &cmps)?;
        }
    }
    load(ctx)?;
    Ok(())
}
