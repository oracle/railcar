use errors::*;
use lazy_static::initialize;
use nix::unistd::Pid;
use num_traits::identities::Zero;
use oci::LinuxDeviceType;
use oci::{LinuxDeviceCgroup, LinuxResources, LinuxThrottleDevice};
use std::collections::HashMap;
use std::fs::{create_dir_all, remove_dir, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::string::ToString;

pub fn init() {
    // initialize lazy_static maps
    initialize(&PATHS);
    initialize(&MOUNTS);
    initialize(&DEFAULT_ALLOWED_DEVICES);
    initialize(&APPLIES);
}

pub fn apply(
    resources: &Option<LinuxResources>,
    pid: &str,
    cgroups_path: &str,
) -> Result<()> {
    for key in MOUNTS.keys() {
        let dir = if let Some(s) = path(key, cgroups_path) {
            s
        } else {
            continue;
        };
        // ensure cgroup dir
        debug!{"creating cgroup dir {}", &dir};
        let chain = || format!("create cgroup dir {} failed", &dir);
        create_dir_all(&dir).chain_err(chain)?;
        // enter cgroups
        for k in key.split(',') {
            if let Some(cgroup_apply) = APPLIES.get(k) {
                if let Some(ref r) = *resources {
                    cgroup_apply(r, &dir)?;
                } else {
                    // apply with empty resources
                    cgroup_apply(&LinuxResources::default(), &dir)?;
                }
                write_file(&dir, "cgroup.procs", pid)?;
            }
        }
    }
    Ok(())
}

pub fn remove(cgroups_path: &str) -> Result<()> {
    for key in MOUNTS.keys() {
        let dir = if let Some(s) = path(key, cgroups_path) {
            s
        } else {
            continue;
        };
        debug!{"removing cgroup dir {}", &dir};
        // remove cgroup dir
        let chain = || format!("remove cgroup dir {} failed", &dir);
        remove_dir(&dir).chain_err(chain)?;
    }
    Ok(())
}

#[inline]
fn wrnz<T: ToString + Zero>(
    dir: &str,
    key: &str,
    value: Option<T>,
) -> Result<()> {
    match value {
        Some(val) => {
            if !val.is_zero() {
                write_file(dir, key, &val.to_string())
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

#[inline]
fn try_wrnz<T: ToString + Zero>(
    dir: &str,
    key: &str,
    value: Option<T>,
) -> Result<()> {
    match wrnz(dir, key, value) {
        Err(Error(ErrorKind::Io(e), x)) => {
            if e.kind() == ::std::io::ErrorKind::PermissionDenied {
                warn!{"setting cgroup value {} is not supported", key}
                Ok(())
            } else {
                Err(Error(ErrorKind::Io(e), x))
            }
        }
        x => x,
    }
}

pub fn write_file(dir: &str, file: &str, data: &str) -> Result<()> {
    let path = format!{"{}/{}", dir, file};
    debug!{"writing {} to {}", data, &path};
    let mut f = File::create(&path)?;
    f.write_all(data.as_bytes())?;
    Ok(())
}

pub fn read_file(dir: &str, file: &str) -> Result<(String)> {
    let path = format!{"{}/{}", dir, file};
    let mut f = File::open(&path)?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    debug!{"read {} from {}", &result, &path};
    Ok(result)
}

pub fn path(key: &str, cgroups_path: &str) -> Option<String> {
    let mount = MOUNTS.get(key);
    let rel = PATHS.get(key);
    if mount.is_none() || rel.is_none() {
        None
    } else if rel.unwrap() == "/" {
        Some(format!{"{}{}", &mount.unwrap(), cgroups_path})
    } else {
        Some(format!{"{}{}{}", &mount.unwrap(), &rel.unwrap(), cgroups_path})
    }
}

pub fn get_procs(key: &str, cgroups_path: &str) -> Vec<Pid> {
    let mut result = Vec::new();
    if let Some(dir) = path(key, cgroups_path) {
        let path = format!{"{}/cgroup.procs", dir};
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!{"could not cgroup.procs: {}", e};
                return result;
            }
        };
        for line in BufReader::new(f).lines() {
            let l = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("failed to read cgroup info: {}", e);
                    return result;
                }
            };
            if let Ok(pid) = l.parse::<i32>() {
                result.push(Pid::from_raw(pid));
            }
        }
    }
    result
}

lazy_static! {
    pub static ref PATHS: HashMap<String, String> = {
        let mut result = HashMap::new();
        let f = match File::open("/proc/self/cgroup") {
            Ok(f) => f,
            Err(e) => {
                warn!{"could not load cgroup info: {}", e};
                return result;
            }
        };

        for line in BufReader::new(f).lines() {
            let l = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("failed to read cgroup info: {}", e);
                    return result;
                }
            };
            let fields: Vec<&str> = l.split(':').collect();
            if fields.len() != 3 {
                warn!("cgroup data is corrupted");
                continue;
            }
            result.insert(fields[1].to_string(), fields[2].to_string());
        }

        result
    };
}

lazy_static! {
    pub static ref MOUNTS: HashMap<String, String> = {
        let mut result = HashMap::new();
        let f = match File::open("/proc/self/mountinfo") {
            Ok(f) => f,
            Err(e) => {
                warn!{"could not load mount info: {}", e};
                return result;
            }
        };
        for line in BufReader::new(f).lines() {
            let l = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("failed to read mount info: {}", e);
                    return result;
                }
            };
            if let Some(sep) = l.find(" - ") {
                if l.len() < sep + 10 {
                    continue;
                }
                let key = &l[sep + 3..sep + 10];
                if key != "cgroup " && key != "cgroup2" {
                    continue;
                }
                let pre: Vec<&str> = l[..sep].split(' ').collect();
                if pre.len() != 7 {
                    warn!("mountinfo data is corrupted");
                    continue;
                }
                let post: Vec<&str> = l[sep + 3..].split(' ').collect();
                if post.len() != 3 {
                    warn!("mountinfo data is corrupted");
                    continue;
                }
                let mut offset = post[2].len();
                while let Some(o) = post[2][..offset].rfind(',') {
                    let name = &post[2][o + 1..];
                    if PATHS.contains_key(name) {
                        result.insert(name.to_string(), pre[4].to_string());
                        break;
                    }
                    offset = o;
                }
            } else {
                warn!("mountinfo data is corrupted");
            }
        }
        result
    };
}

lazy_static! {
    static ref DEFAULT_ALLOWED_DEVICES: Vec<LinuxDeviceCgroup> = {
        let mut v = Vec::new();
        // mknod any device
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::c,
            major: None,
            minor: None,
            access: "m".to_string(),
        });
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::b,
            major: None,
            minor: None,
            access: "m".to_string(),
        });
        // /dev/console
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::c,
            major: Some(5),
            minor: Some(1),
            access: "rwm".to_string(),
        });
        // /dev/pts
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::c,
            major: Some(136),
            minor: None,
            access: "rwm".to_string(),
        });
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::c,
            major: Some(5),
            minor: Some(2),
            access: "rwm".to_string(),
        });
        // tun/tap
        v.push(LinuxDeviceCgroup{
            allow: true,
            typ: LinuxDeviceType::c,
            major: Some(10),
            minor: Some(200),
            access: "rwm".to_string(),
        });
        v
    };
}

type Apply = fn(&LinuxResources, &str) -> Result<()>;

lazy_static! {
    static ref APPLIES: HashMap<&'static str, Apply> = {
        let mut m: HashMap<&'static str, Apply> = HashMap::new();
        m.insert("cpuacct", null_apply); // no settings for cpuacct
        m.insert("perf_event", null_apply); // no settings for perf_event
        m.insert("freezer", null_apply); // no settings for freezer
        m.insert("name=systemd", null_apply); // no settings for systemd
        m.insert("cpuset", cpuset_apply);
        m.insert("cpu", cpu_apply);
        m.insert("memory", memory_apply);
        m.insert("blkio", blkio_apply);
        m.insert("pids", pids_apply);
        m.insert("net_cls", net_cls_apply);
        m.insert("net_prio", net_prio_apply);
        m.insert("hugetlb", hugetlb_apply);
        m.insert("devices", devices_apply);
        m
    };
}

fn copy_parent(dir: &str, file: &str) -> Result<()> {
    let parent = if let Some(o) = dir.rfind('/') {
        &dir[..o]
    } else {
        bail!{"failed to find {} in parent cgroups", file};
    };
    match read_file(parent, file) {
        Err(Error(ErrorKind::Io(e), _)) => {
            if e.kind() == ::std::io::ErrorKind::NotFound {
                // copy parent and then retry
                copy_parent(parent, file)?;
                return copy_parent(dir, file);
            }
            let msg = "failed to copy parent cgroup".to_string();
            Err(e).chain_err(|| msg)
        }
        Err(e) => Err(e),
        Ok(data) => write_file(dir, file, &data),
    }
}

fn null_apply(_: &LinuxResources, _: &str) -> Result<()> {
    Ok(())
}

fn cpuset_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    // cpuset files are required so copy them from the parent
    let (cpus, mems) = if let Some(cpu) = r.cpu.as_ref() {
        (&cpu.cpus[..], &cpu.mems[..])
    } else {
        ("", "")
    };

    if cpus.is_empty() {
        copy_parent(dir, "cpuset.cpus")?;
    } else {
        write_file(dir, "cpuset.cpus", cpus)?;
    }
    if mems.is_empty() {
        copy_parent(dir, "cpuset.mems")?;
    } else {
        write_file(dir, "cpuset.mems", mems)?;
    }
    Ok(())
}

fn cpu_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    if let Some(cpu) = r.cpu.as_ref() {
        // NOTE: these values are nullable in the spec, but runc treats
        //       null as a zero value
        try_wrnz(dir, "cpu.rt_period_us", cpu.realtime_period)?;
        try_wrnz(dir, "cpu.rt_runtime_us", cpu.realtime_runtime)?;
        wrnz(dir, "cpu.shares", cpu.shares)?;
        wrnz(dir, "cpu.cfs_quota_us", cpu.quota)?;
        wrnz(dir, "cpu.cfs_period_us", cpu.period)?;
    };
    Ok(())
}
fn memory_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    // TODO: handle issues with joining an existing namespace
    if let Some(memory) = r.memory.as_ref() {
        // NOTE: these values are nullable in the spec, but runc treats
        //       null as a zero value
        wrnz(dir, "memory.limit_in_bytes", memory.limit)?;
        wrnz(dir, "memory.soft_limit_in_bytes", memory.reservation)?;
        // NOTE: these two can be disabled in the kernel, so just warn
        //       if they are not set
        try_wrnz(dir, "memory.memsw.limit_in_bytes", memory.swap)?;
        try_wrnz(dir, "memory.kmem.limit_in_bytes", memory.kernel)?;
        wrnz(dir, "memory.kmem.tcp.limit_in_bytes", memory.kernel_tcp)?;
        if let Some(s) = memory.swappiness {
            // NOTE: docker sends an invalid value for swappiness
            if s <= 100 {
                wrnz(dir, "memory.swappiness", memory.swappiness)?;
            } else {
                warn!{"memory swappiness invalid, working around bug"};
            }
        }
        if r.disable_oom_killer {
            write_file(dir, "memory.oom_control", "1")?;
        }
    };
    Ok(())
}

#[inline]
fn rate(d: &LinuxThrottleDevice) -> String {
    return format!{"{}:{} {}", d.major, d.minor, d.rate};
}

fn blkio_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    if let Some(blkio) = r.block_io.as_ref() {
        // NOTE: these values are nullable in the spec, but runc treats
        //       null as a zero value
        wrnz(dir, "blkio.weight", blkio.weight)?;
        wrnz(dir, "blkio.leaf_weight", blkio.leaf_weight)?;
        for d in &blkio.weight_device {
            // NOTE: runc writes zero values here. This may be a bug, but
            //       we are duplicating functionality.
            if let Some(w) = d.weight {
                let weight = format!{"{}:{} {}", d.major, d.minor, w};
                write_file(dir, "blkio.weight_device", &weight)?;
            }
            if let Some(w) = d.leaf_weight {
                let weight = format!{"{}:{} {}", d.major, d.minor, w};
                write_file(dir, "blkio.leaf_weight_device", &weight)?;
            }
        }
        for d in &blkio.throttle_read_bps_device {
            write_file(dir, "blkio.throttle.read_bps_device", &rate(d))?;
        }
        for d in &blkio.throttle_write_bps_device {
            write_file(dir, "blkio.throttle.write_bps_device", &rate(d))?;
        }
        for d in &blkio.throttle_read_iops_device {
            write_file(dir, "blkio.throttle.read_iops_device", &rate(d))?;
        }
        for d in &blkio.throttle_write_iops_device {
            write_file(dir, "blkio.throttle.write_iops_device", &rate(d))?;
        }
    }
    Ok(())
}

fn pids_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    if let Some(pids) = r.pids.as_ref() {
        if pids.limit > 0 {
            write_file(dir, "pids.max", &pids.limit.to_string())?;
        } else {
            write_file(dir, "pids.max", "max")?;
        };
    }
    Ok(())
}

fn net_cls_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    if let Some(network) = r.network.as_ref() {
        wrnz(dir, "net_cls.classid", network.class_id)?;
    }
    Ok(())
}

fn net_prio_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    if let Some(network) = r.network.as_ref() {
        for p in &network.priorities {
            let prio = format!{"{} {}", p.name, p.priority};
            write_file(dir, "net_prio.ifpriomap", &prio)?;
        }
    }
    Ok(())
}

fn hugetlb_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    for h in &r.hugepage_limits {
        let key = format!{"hugetlb.{}.limit_in_bytes", h.page_size};
        write_file(dir, &key, &h.limit.to_string())?;
    }
    Ok(())
}

fn write_device(d: &LinuxDeviceCgroup, dir: &str) -> Result<()> {
    let key = if d.allow {
        "devices.allow"
    } else {
        "devices.deny"
    };
    let typ = match d.typ {
        LinuxDeviceType::b => "b",
        LinuxDeviceType::c => "c",
        LinuxDeviceType::a => "a",
        _ => {
            let msg = "invalid cgroup device type".to_string();
            bail!(ErrorKind::InvalidSpec(msg));
        }
    };
    let major = if let Some(x) = d.major {
        x.to_string()
    } else {
        "*".to_string()
    };
    let minor = if let Some(x) = d.minor {
        x.to_string()
    } else {
        "*".to_string()
    };
    let val = format!{"{} {}:{} {}", typ, &major, &minor, &d.access};
    write_file(dir, key, &val)
}

fn devices_apply(r: &LinuxResources, dir: &str) -> Result<()> {
    for d in &r.devices {
        write_device(d, dir)?;
    }
    for d in super::DEFAULT_DEVICES.iter() {
        let ld = LinuxDeviceCgroup {
            allow: true,
            typ: d.typ,
            major: Some(d.major as i64),
            minor: Some(d.minor as i64),
            access: "rwm".to_string(),
        };

        write_device(&ld, dir)?;
    }
    for ld in DEFAULT_ALLOWED_DEVICES.iter() {
        write_device(ld, dir)?;
    }

    Ok(())
}
