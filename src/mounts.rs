use cgroups;
use errors::*;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::mount::MsFlags;
use nix::mount::*;
use nix::sys::stat::{mknod, umask};
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::{chdir, chown, close, getcwd, pivot_root};
use nix::unistd::{Gid, Uid};
use nix::NixPath;
use nix_ext::fchdir;
use oci::{LinuxDevice, LinuxDeviceType, Mount, Spec};
use selinux::setfilecon;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::fs::{canonicalize, create_dir_all, remove_file};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

pub fn init_rootfs(
    spec: &Spec,
    rootfs: &str,
    cpath: &str,
    bind_devices: bool,
) -> Result<()> {
    // set namespace propagation
    let mut flags = MsFlags::MS_REC;
    match spec.linux {
        Some(ref linux) => match linux.rootfs_propagation.as_ref() {
            "shared" => {
                flags |= MsFlags::MS_SHARED;
                Ok(())
            }
            "private" => {
                flags |= MsFlags::MS_PRIVATE;
                Ok(())
            }
            "slave" | "" => {
                flags |= MsFlags::MS_SLAVE;
                Ok(())
            }
            _ => {
                let msg = format!(
                    "invalid propogation value: {}",
                    linux.rootfs_propagation
                );
                Err(Error::from(ErrorKind::InvalidSpec(msg)))
            }
        },
        None => {
            flags |= MsFlags::MS_SLAVE;
            Ok(())
        }
    }?;
    let linux = spec.linux.as_ref().unwrap();
    mount(None::<&str>, "/", None::<&str>, flags, None::<&str>)?;

    // mount root dir
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    for m in &spec.mounts {
        // TODO: check for nasty destinations involving symlinks and illegal
        //       locations.
        // NOTE: this strictly is less permissive than runc, which allows ..
        //       as long as the resulting path remains in the rootfs. There
        //       is no good reason to allow this so we just forbid it
        if !m.destination.starts_with('/') || m.destination.contains("..") {
            let msg = format!("invalid mount destination: {}", m.destination);
            return Err(ErrorKind::InvalidSpec(msg).into());
        }
        let (flags, data) = parse_mount(m);
        if m.typ == "cgroup" {
            mount_cgroups(m, rootfs, flags, &data, &linux.mount_label, cpath)?;
        } else if m.destination == "/dev" {
            // dev can't be read only yet because we have to mount devices
            mount_from(
                m,
                rootfs,
                flags & !MsFlags::MS_RDONLY,
                &data,
                &linux.mount_label,
            )?;
        } else {
            mount_from(m, rootfs, flags, &data, &linux.mount_label)?;
        }
    }

    // chdir into the rootfs so we can make devices with simpler paths
    let olddir = getcwd()?;
    chdir(rootfs)?;

    default_symlinks()?;
    create_devices(&linux.devices, bind_devices)?;
    ensure_ptmx()?;

    chdir(&olddir)?;

    Ok(())
}

pub fn pivot_rootfs<P: ?Sized + NixPath>(path: &P) -> Result<()> {
    let oldroot =
        open("/", OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())?;
    defer!(close(oldroot).unwrap());
    let newroot =
        open(path, OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())?;
    defer!(close(newroot).unwrap());
    pivot_root(path, path)?;
    umount2("/", MntFlags::MNT_DETACH)?;
    fchdir(newroot)?;
    Ok(())
}

pub fn finish_rootfs(spec: &Spec) -> Result<()> {
    if let Some(ref linux) = spec.linux {
        for path in &linux.masked_paths {
            mask_path(path)?;
        }
        for path in &linux.readonly_paths {
            readonly_path(path)?;
        }
    }

    // remount dev ro if necessary
    for m in &spec.mounts {
        if m.destination == "/dev" {
            let (flags, _) = parse_mount(m);
            if flags.contains(MsFlags::MS_RDONLY) {
                mount(
                    Some("/dev"),
                    "/dev",
                    None::<&str>,
                    flags | MsFlags::MS_REMOUNT,
                    None::<&str>,
                )?;
            }
        }
    }

    if spec.root.readonly {
        let flags = MsFlags::MS_BIND
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NODEV
            | MsFlags::MS_REMOUNT;
        mount(Some("/"), "/", None::<&str>, flags, None::<&str>)?;
    }

    umask(Mode::from_bits_truncate(0o022));
    Ok(())
}

#[cfg_attr(rustfmt, rustfmt_skip)]
lazy_static! {
    static ref OPTIONS: HashMap<&'static str, (bool, MsFlags)> = {
        let mut m = HashMap::new();
        m.insert("defaults",      (false, MsFlags::empty()));
        m.insert("ro",            (false, MsFlags::MS_RDONLY));
        m.insert("rw",            (true,  MsFlags::MS_RDONLY));
        m.insert("suid",          (true,  MsFlags::MS_NOSUID));
        m.insert("nosuid",        (false, MsFlags::MS_NOSUID));
        m.insert("dev",           (true,  MsFlags::MS_NODEV));
        m.insert("nodev",         (false, MsFlags::MS_NODEV));
        m.insert("exec",          (true,  MsFlags::MS_NOEXEC));
        m.insert("noexec",        (false, MsFlags::MS_NOEXEC));
        m.insert("sync",          (false, MsFlags::MS_SYNCHRONOUS));
        m.insert("async",         (true,  MsFlags::MS_SYNCHRONOUS));
        m.insert("dirsync",       (false, MsFlags::MS_DIRSYNC));
        m.insert("remount",       (false, MsFlags::MS_REMOUNT));
        m.insert("mand",          (false, MsFlags::MS_MANDLOCK));
        m.insert("nomand",        (true,  MsFlags::MS_MANDLOCK));
        m.insert("atime",         (true,  MsFlags::MS_NOATIME));
        m.insert("noatime",       (false, MsFlags::MS_NOATIME));
        m.insert("diratime",      (true,  MsFlags::MS_NODIRATIME));
        m.insert("nodiratime",    (false, MsFlags::MS_NODIRATIME));
        m.insert("bind",          (false, MsFlags::MS_BIND));
        m.insert("rbind",         (false, MsFlags::MS_BIND | MsFlags::MS_REC));
        m.insert("unbindable",    (false, MsFlags::MS_UNBINDABLE));
        m.insert("runbindable",   (false, MsFlags::MS_UNBINDABLE | MsFlags::MS_REC));
        m.insert("private",       (false, MsFlags::MS_PRIVATE));
        m.insert("rprivate",      (false, MsFlags::MS_PRIVATE | MsFlags::MS_REC));
        m.insert("shared",        (false, MsFlags::MS_SHARED));
        m.insert("rshared",       (false, MsFlags::MS_SHARED | MsFlags::MS_REC));
        m.insert("slave",         (false, MsFlags::MS_SLAVE));
        m.insert("rslave",        (false, MsFlags::MS_SLAVE | MsFlags::MS_REC));
        m.insert("relatime",      (false, MsFlags::MS_RELATIME));
        m.insert("norelatime",    (true,  MsFlags::MS_RELATIME));
        m.insert("strictatime",   (false, MsFlags::MS_STRICTATIME));
        m.insert("nostrictatime", (true,  MsFlags::MS_STRICTATIME));
        m
    };
}

fn mount_cgroups(
    m: &Mount,
    rootfs: &str,
    flags: MsFlags,
    data: &str,
    label: &str,
    cpath: &str,
) -> Result<()> {
    let cm = Mount {
        source: "tmpfs".to_string(),
        typ: "tmpfs".to_string(),
        destination: m.destination.clone(),
        options: Vec::new(),
    };
    let cflags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    // mount tmpfs for mounts
    mount_from(&cm, rootfs, cflags, "", label)?;
    for (key, mount_path) in cgroups::MOUNTS.iter() {
        let source = if let Some(s) = cgroups::path(key, cpath) {
            s
        } else {
            continue;
        };

        // NOTE: this will bind mount over the same location if two
        //       cgroups are mounted to directories with the same
        //       value at the end of the path, for example:
        //       /path/to/a/cgroup /path/to/b/cgroup
        //       runc mounts by using the final path component, so
        //       we do the same thing here.
        let base = if let Some(o) = mount_path.rfind('/') {
            &mount_path[o + 1..]
        } else {
            &mount_path[..]
        };
        let dest = format!{"{}/{}", &m.destination, &base};
        let bm = Mount {
            source: source,
            typ: "bind".to_string(),
            destination: dest,
            options: Vec::new(),
        };
        mount_from(
            &bm,
            rootfs,
            flags | MsFlags::MS_BIND | MsFlags::MS_REC,
            data,
            label,
        )?;
        for k in key.split(',') {
            if k != key {
                // try to create a symlink for combined strings
                let dest = format!{"{}{}/{}", rootfs, &m.destination, &k};
                symlink(key, &dest)?;
            }
        }
    }
    // remount readonly if necessary
    if flags.contains(MsFlags::MS_RDONLY) {
        let dest = format!{"{}{}", rootfs, &m.destination};
        mount(
            Some(&*dest),
            &*dest,
            None::<&str>,
            cflags | MsFlags::MS_BIND | MsFlags::MS_REMOUNT,
            None::<&str>,
        )?;
    }
    Ok(())
}

fn parse_mount(m: &Mount) -> (MsFlags, String) {
    let mut flags = MsFlags::empty();
    let mut data = Vec::new();
    for s in &m.options {
        match OPTIONS.get(s.as_str()) {
            Some(x) => {
                let (clear, f) = *x;
                if clear {
                    flags &= !f;
                } else {
                    flags |= f;
                }
            }
            None => {
                data.push(s.as_str());
            }
        };
    }
    (flags, data.join(","))
}

fn mount_from(
    m: &Mount,
    rootfs: &str,
    flags: MsFlags,
    data: &str,
    label: &str,
) -> Result<()> {
    let d;
    if !label.is_empty() && m.typ != "proc" && m.typ != "sysfs" {
        if data.is_empty() {
            d = format!{"context=\"{}\"", label};
        } else {
            d = format!{"{},context=\"{}\"", data, label};
        }
    } else {
        d = data.to_string();
    }

    let dest = format!{"{}{}", rootfs, &m.destination};

    debug!(
        "mounting {} to {} as {} with data '{}'",
        &m.source, &m.destination, &m.typ, &d
    );

    let src = if m.typ == "bind" {
        let src = canonicalize(&m.source)?;
        let dir = if src.is_file() {
            Path::new(&dest).parent().unwrap()
        } else {
            Path::new(&dest)
        };
        if let Err(e) = create_dir_all(&dir) {
            debug!("ignoring create dir fail of {:?}: {}", &dir, e)
        }
        // make sure file exists so we can bind over it
        if src.is_file() {
            if let Err(e) =
                OpenOptions::new().create(true).write(true).open(&dest)
            {
                debug!("ignoring touch fail of {:?}: {}", &dest, e)
            }
        }
        src
    } else {
        if let Err(e) = create_dir_all(&dest) {
            debug!("ignoring create dir fail of {:?}: {}", &dest, e)
        }
        PathBuf::from(&m.source)
    };

    if let Err(::nix::Error::Sys(errno)) =
        mount(Some(&*src), &*dest, Some(&*m.typ), flags, Some(&*d))
    {
        if errno != Errno::EINVAL {
            let chain = || format!("mount of {} failed", &m.destination);
            return Err(::nix::Error::Sys(errno)).chain_err(chain)?;
        }
        // try again without mount label
        mount(Some(&*src), &*dest, Some(&*m.typ), flags, Some(data))?;
        // warn if label cannot be set
        if let Err(e) = setfilecon(&dest, label) {
            warn!{"could not set mount label of {} to {}: {}",
            &m.destination, &label, e};
        }
    }
    // remount bind mounts if they have other flags (like MsFlags::MS_RDONLY)
    if flags.contains(MsFlags::MS_BIND)
        && flags.intersects(
            !(MsFlags::MS_REC
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_PRIVATE
                | MsFlags::MS_SHARED
                | MsFlags::MS_SLAVE),
        ) {
        let chain = || format!("remount of {} failed", &dest);
        mount(
            Some(&*dest),
            &*dest,
            None::<&str>,
            flags | MsFlags::MS_REMOUNT,
            None::<&str>,
        ).chain_err(chain)?;
    }
    Ok(())
}

static SYMLINKS: &'static [(&'static str, &'static str)] = &[
    ("/proc/self/fd", "dev/fd"),
    ("/proc/self/fd/0", "dev/stdin"),
    ("/proc/self/fd/1", "dev/stdout"),
    ("/proc/self/fd/2", "dev/stderr"),
];

fn default_symlinks() -> Result<()> {
    if Path::new("/proc/kcore").exists() {
        symlink("/proc/kcore", "dev/kcore")?;
    }
    for &(src, dst) in SYMLINKS {
        symlink(src, dst)?;
    }
    Ok(())
}
fn create_devices(devices: &[LinuxDevice], bind: bool) -> Result<()> {
    let op: fn(&LinuxDevice) -> Result<()> =
        if bind { bind_dev } else { mknod_dev };
    let old = umask(Mode::from_bits_truncate(0o000));
    for dev in super::DEFAULT_DEVICES.iter() {
        op(dev)?;
    }
    for dev in devices {
        if !dev.path.starts_with("/dev") || dev.path.contains("..") {
            let msg = format!("{} is not a valid device path", dev.path);
            bail!(ErrorKind::InvalidSpec(msg));
        }
        op(dev)?;
    }
    umask(old);
    Ok(())
}

fn ensure_ptmx() -> Result<()> {
    if let Err(e) = remove_file("dev/ptmx") {
        if e.kind() != ::std::io::ErrorKind::NotFound {
            let msg = "could not delete /dev/ptmx".to_string();
            Err(e).chain_err(|| msg)?;
        }
    }
    symlink("pts/ptmx", "dev/ptmx")?;
    Ok(())
}

fn makedev(major: u64, minor: u64) -> u64 {
    (minor & 0xff)
        | ((major & 0xfff) << 8)
        | ((minor & !0xff) << 12)
        | ((major & !0xfff) << 32)
}

fn to_sflag(t: LinuxDeviceType) -> Result<SFlag> {
    Ok(match t {
        LinuxDeviceType::b => SFlag::S_IFBLK,
        LinuxDeviceType::c | LinuxDeviceType::u => SFlag::S_IFCHR,
        LinuxDeviceType::p => SFlag::S_IFIFO,
        LinuxDeviceType::a => {
            let msg = "type a is not allowed for linux device".to_string();
            bail!(ErrorKind::InvalidSpec(msg));
        }
    })
}

fn mknod_dev(dev: &LinuxDevice) -> Result<()> {
    let f = to_sflag(dev.typ)?;
    debug!("mknoding {}", &dev.path);
    mknod(
        &dev.path[1..],
        f,
        Mode::from_bits_truncate(dev.file_mode.unwrap_or(0)),
        makedev(dev.major, dev.minor),
    )?;
    chown(
        &dev.path[1..],
        dev.uid.map(|n| Uid::from_raw(n)),
        dev.gid.map(|n| Gid::from_raw(n)),
    )?;
    Ok(())
}

fn bind_dev(dev: &LinuxDevice) -> Result<()> {
    let fd = open(
        &dev.path[1..],
        OFlag::O_RDWR | OFlag::O_CREAT,
        Mode::from_bits_truncate(0o644),
    )?;
    close(fd)?;
    debug!("bind mounting {}", &dev.path);
    mount(
        Some(&*dev.path),
        &dev.path[1..],
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    Ok(())
}

fn mask_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.contains("..") {
        let msg = format!("invalid maskedPath: {}", path);
        return Err(ErrorKind::InvalidSpec(msg).into());
    }

    if let Err(::nix::Error::Sys(errno)) = mount(
        Some("/dev/null"),
        path,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    ) {
        // ignore ENOENT and ENOTDIR: path to mask doesn't exist
        if errno != Errno::ENOENT && errno != Errno::ENOTDIR {
            let msg = format!("could not mask {}", path);
            Err(::nix::Error::Sys(errno)).chain_err(|| msg)?;
        } else {
            debug!("ignoring mask of {} because it doesn't exist", path);
        }
    }
    Ok(())
}

fn readonly_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.contains("..") {
        let msg = format!("invalid readonlyPath: {}", path);
        return Err(ErrorKind::InvalidSpec(msg).into());
    }
    if let Err(e) = mount(
        Some(&path[1..]),
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ) {
        match e {
            ::nix::Error::Sys(errno) => {
                // ignore ENOENT: path to make read only doesn't exist
                if errno != Errno::ENOENT {
                    let msg = format!("could not readonly {}", path);
                    Err(e).chain_err(|| msg)?;
                }
                debug!("ignoring remount of {} because it doesn't exist", path);
                return Ok(());
            }
            _ => {
                unreachable!("Supposedly unreachable error {:?}", e);
            }
        }
    }
    mount(
        Some(&path[1..]),
        &path[1..],
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REC
            | MsFlags::MS_RDONLY
            | MsFlags::MS_REMOUNT,
        None::<&str>,
    )?;
    Ok(())
}
