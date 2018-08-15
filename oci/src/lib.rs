#![allow(non_camel_case_types)]
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
//extern crate nix;

pub mod serialize;

use std::collections::HashMap;
use std::io::Write;

use serde_json::Value;

//use nix::unistd::{Gid,Pid,Uid};

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Platform {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arch: String,
}

#[derive(Default, PartialEq, Serialize, Deserialize, Debug)]
pub struct Box {
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub width: u64,
}

fn is_default<T: Default + PartialEq>(b: &T) -> bool {
    *b == T::default()
}


#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "additionalGids")]
    pub additional_gids: Vec<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
}

// this converts directly to the correct int
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum LinuxRlimitType {
    RLIMIT_CPU, // CPU time in sec
    RLIMIT_FSIZE, // Maximum filesize
    RLIMIT_DATA, // max data size
    RLIMIT_STACK, // max stack size
    RLIMIT_CORE, // max core file size
    RLIMIT_RSS, // max resident set size
    RLIMIT_NPROC, // max number of processes
    RLIMIT_NOFILE, // max number of open files
    RLIMIT_MEMLOCK, // max locked-in-memory address space
    RLIMIT_AS, // address space limit
    RLIMIT_LOCKS, // maximum file locks held
    RLIMIT_SIGPENDING, // max number of pending signals
    RLIMIT_MSGQUEUE, // maximum bytes in POSIX mqueues
    RLIMIT_NICE, // max nice prio allowed to raise to
    RLIMIT_RTPRIO, // maximum realtime priority
    RLIMIT_RTTIME, // timeout for RT tasks in us
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxRlimit {
    #[serde(rename = "type")]
    pub typ: LinuxRlimitType,
    #[serde(default)]
    pub hard: u64,
    #[serde(default)]
    pub soft: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum LinuxCapabilityType {
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_DAC_READ_SEARCH,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_LINUX_IMMUTABLE,
    CAP_NET_BIND_SERVICE,
    CAP_NET_BROADCAST,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_IPC_LOCK,
    CAP_IPC_OWNER,
    CAP_SYS_MODULE,
    CAP_SYS_RAWIO,
    CAP_SYS_CHROOT,
    CAP_SYS_PTRACE,
    CAP_SYS_PACCT,
    CAP_SYS_ADMIN,
    CAP_SYS_BOOT,
    CAP_SYS_NICE,
    CAP_SYS_RESOURCE,
    CAP_SYS_TIME,
    CAP_SYS_TTY_CONFIG,
    CAP_MKNOD,
    CAP_LEASE,
    CAP_AUDIT_WRITE,
    CAP_AUDIT_CONTROL,
    CAP_SETFCAP,
    CAP_MAC_OVERRIDE,
    CAP_MAC_ADMIN,
    CAP_SYSLOG,
    CAP_WAKE_ALARM,
    CAP_BLOCK_SUSPEND,
    CAP_AUDIT_READ,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCapabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<LinuxCapabilityType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<LinuxCapabilityType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<LinuxCapabilityType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<LinuxCapabilityType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient: Vec<LinuxCapabilityType>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    #[serde(default, skip_serializing_if = "is_false")]
    pub terminal: bool,
    #[serde(default, skip_serializing_if = "is_default",
            rename = "consoleSize")]
    pub console_size: Box,
    pub user: User,
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(default, deserialize_with = "deserialize_capabilities",
            skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<LinuxCapabilities>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<LinuxRlimit>,
    #[serde(default, skip_serializing_if = "is_false",
            rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "apparmorProfile")]
    pub apparmor_profile: String,
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "selinuxLabel")]
    pub selinux_label: String,
}

use serde::Deserialize;

fn cap_from_array<D>(
    a: &[serde_json::Value],
) -> Result<Vec<LinuxCapabilityType>, D::Error>
where
    D: serde::Deserializer,
{
    let mut caps = Vec::new();
    for c in a {
        match LinuxCapabilityType::deserialize(c) {
            Ok(val) => caps.push(val),
            Err(_) => {
                let msg = format!("Capability '{}' is not valid", c);
                return Err(serde::de::Error::custom(msg));
            }
        }
    }
    Ok(caps)
}

fn cap_from_object<D>(
    o: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<LinuxCapabilityType>, D::Error>
where
    D: serde::Deserializer,
{
    if let Some(v) = o.get(key) {
        match *v {
            serde_json::Value::Null => Ok(Vec::new()),
            serde_json::Value::Array(ref a) => cap_from_array::<D>(a),
            _ => Err(serde::de::Error::custom(
                "Unexpected value in capability set",
            )),
        }
    } else {
        Ok(Vec::new())
    }
}

// handle the old case where caps was just a list of caps
fn deserialize_capabilities<D>(
    de: D,
) -> Result<Option<LinuxCapabilities>, D::Error>
where
    D: serde::Deserializer,
{
    let r: serde_json::Value = serde::Deserialize::deserialize(de)?;
    match r {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Array(a) => {
            let caps = cap_from_array::<D>(&a)?;
            let capabilities = LinuxCapabilities {
                bounding: caps.clone(),
                effective: caps.clone(),
                inheritable: caps.clone(),
                permitted: caps.clone(),
                ambient: caps.clone(),
            };

            Ok(Some(capabilities))
        }
        serde_json::Value::Object(o) => {
            let capabilities = LinuxCapabilities{
                bounding: cap_from_object::<D>(&o, "bounding")?,
                effective: cap_from_object::<D>(&o, "effective")?,
                inheritable: cap_from_object::<D>(&o, "inheritable")?,
                permitted: cap_from_object::<D>(&o, "permitted")?,
                ambient: cap_from_object::<D>(&o, "ambient")?,
            };

            Ok(Some(capabilities))
        }
        _ => Err(serde::de::Error::custom("Unexpected value in capabilites")),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    #[serde(default)]
    pub path: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub readonly: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Mount {
    #[serde(default)]
    pub destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "type")]
    pub typ: String,
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hook {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hooks {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prestart: Vec<Hook>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststart: Vec<Hook>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststop: Vec<Hook>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxIDMapping {
    #[serde(default, rename = "hostID")]
    pub host_id: u32,
    #[serde(default, rename = "containerID")]
    pub container_id: u32,
    #[serde(default)]
    pub size: u32,
}

// a is for LinuxDeviceCgroup
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum LinuxDeviceType {
    b,
    c,
    u,
    p,
    a,
}

impl Default for LinuxDeviceType {
    fn default() -> LinuxDeviceType {
        LinuxDeviceType::a
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDeviceCgroup {
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow: bool,
    #[serde(default, rename = "type")]
    pub typ: LinuxDeviceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "kernelTCP")]
    pub kernel_tcp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swappiness: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCPU {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "realtimeRuntime")]
    pub realtime_runtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "realtimePeriod")]
    pub realtime_period: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpus: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mems: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxPids {
    #[serde(default)]
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxWeightDevice {
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "leafWeight")]
    pub leaf_weight: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxThrottleDevice {
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
    #[serde(default)]
    pub rate: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxBlockIO {
    #[serde(skip_serializing_if = "Option::is_none", rename = "blkioWeight")]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "blkioLeafWeight")]
    pub leaf_weight: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "blkioWeightDevice")]
    pub weight_device: Vec<LinuxWeightDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "blkioThrottleReadBpsDevice")]
    pub throttle_read_bps_device: Vec<LinuxThrottleDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "blkioThrottleWriteBpsDevice")]
    pub throttle_write_bps_device: Vec<LinuxThrottleDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "blkioThrottleReadIOPSDevice")]
    pub throttle_read_iops_device: Vec<LinuxThrottleDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "blkioThrottleWriteIOPSDevice")]
    pub throttle_write_iops_device: Vec<LinuxThrottleDevice>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxHugepageLimit {
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "pageSize")]
    pub page_size: String,
    #[serde(default)]
    pub limit: i64,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxInterfacePriority {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default)]
    pub priority: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNetwork {
    #[serde(skip_serializing_if = "Option::is_none", rename = "classID")]
    pub class_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priorities: Vec<LinuxInterfacePriority>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct LinuxResources {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<LinuxDeviceCgroup>,
    // NOTE: spec uses a pointer here, so perhaps this should be an Option, but
    //       false == unset so we don't bother.
    #[serde(default, skip_serializing_if = "is_false",
            rename = "disableOOMKiller")]
    pub disable_oom_killer: bool,
    // NOTE: spec refers to this as an isize but the range is -1000 to 1000, so
    //       an i32 seems just fine
    #[serde(skip_serializing_if = "Option::is_none", rename = "oomScoreAdj")]
    pub oom_score_adj: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<LinuxMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<LinuxCPU>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<LinuxPids>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "blockIO")]
    pub block_io: Option<LinuxBlockIO>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "hugepageLimits")]
    pub hugepage_limits: Vec<LinuxHugepageLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<LinuxNetwork>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum LinuxNamespaceType {
    mount = 0x00020000, /* New mount namespace group */
    cgroup = 0x02000000, /* New cgroup namespace */
    uts = 0x04000000, /* New utsname namespace */
    ipc = 0x08000000, /* New ipc namespace */
    user = 0x10000000, /* New user namespace */
    pid = 0x20000000, /* New pid namespace */
    network = 0x40000000, /* New network namespace */
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub typ: LinuxNamespaceType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDevice {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(rename = "type")]
    pub typ: LinuxDeviceType,
    #[serde(default)]
    pub major: u64,
    #[serde(default)]
    pub minor: u64,
    #[serde(skip_serializing_if = "Option::is_none", rename = "fileMode")]
    pub file_mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u32)]
pub enum LinuxSeccompAction {
    SCMP_ACT_KILL = 0x00000000,
    SCMP_ACT_TRAP = 0x00030000,
    SCMP_ACT_ERRNO = 0x00050001, /* ERRNO + EPERM */
    SCMP_ACT_TRACE = 0x7ff00001, /* TRACE + EPERM */
    SCMP_ACT_ALLOW = 0x7fff0000,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Arch {
    SCMP_ARCH_NATIVE = 0x00000000,
    SCMP_ARCH_X86 = 0x40000003,
    SCMP_ARCH_X86_64 = 0xc000003e,
    SCMP_ARCH_X32 = 0x4000003e,
    SCMP_ARCH_ARM = 0x40000028,
    SCMP_ARCH_AARCH64 = 0xc00000b7,
    SCMP_ARCH_MIPS = 0x00000008,
    SCMP_ARCH_MIPS64 = 0x80000008,
    SCMP_ARCH_MIPS64N32 = 0xa0000008,
    SCMP_ARCH_MIPSEL = 0x40000008,
    SCMP_ARCH_MIPSEL64 = 0xc0000008,
    SCMP_ARCH_MIPSEL64N32 = 0xe0000008,
    SCMP_ARCH_PPC = 0x00000014,
    SCMP_ARCH_PPC64 = 0x80000015,
    SCMP_ARCH_PPC64LE = 0xc0000015,
    SCMP_ARCH_S390 = 0x00000016,
    SCMP_ARCH_S390X = 0x80000016,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u32)]
pub enum LinuxSeccompOperator {
    SCMP_CMP_NE = 1, /* not equal */
    SCMP_CMP_LT = 2, /* less than */
    SCMP_CMP_LE = 3, /* less than or equal */
    SCMP_CMP_EQ = 4, /* equal */
    SCMP_CMP_GE = 5, /* greater than or equal */
    SCMP_CMP_GT = 6, /* greater than */
    SCMP_CMP_MASKED_EQ = 7, /* masked equality */
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSeccompArg {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub value: u64,
    #[serde(default, rename = "valueTwo")]
    pub value_two: u64,
    pub op: LinuxSeccompOperator,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSyscall {
    // old version used name
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    pub action: LinuxSeccompAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<LinuxSeccompArg>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSeccomp {
    #[serde(rename = "defaultAction")]
    pub default_action: LinuxSeccompAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<Arch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<LinuxSyscall>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Linux {
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "uidMappings")]
    pub uid_mappings: Vec<LinuxIDMapping>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "gidMappings")]
    pub gid_mappings: Vec<LinuxIDMapping>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sysctl: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<LinuxResources>,
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "cgroupsPath")]
    pub cgroups_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<LinuxNamespace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<LinuxDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<LinuxSeccomp>,
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "rootfsPropagation")]
    pub rootfs_propagation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "maskedPaths")]
    pub masked_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty",
            rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "mountLabel")]
    pub mount_label: String,
}

// NOTE: Solaris and Windows are ignored for the moment
pub type Solaris = Value;
pub type Windows = Value;


#[derive(Serialize, Deserialize, Debug)]
pub struct Spec {
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "ociVersion")]
    pub version: String,
    // NOTE: Platform was removed, but keeping it as an option
    //       to support older docker versions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    pub process: Process,
    pub root: Root,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solaris: Option<Solaris>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<Windows>,
}

impl Spec {
    pub fn load(path: &str) -> Result<Spec, serialize::SerializeError> {
        serialize::deserialize(path)
    }

    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    #[serde(default, skip_serializing_if = "String::is_empty",
            rename = "ociVersion")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default)]
    pub pid: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bundle: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

impl State {
    pub fn to_string(&self) -> Result<String, serialize::SerializeError> {
        serialize::to_string(self)
    }

    pub fn to_writer<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), serialize::SerializeError> {
        serialize::to_writer(self, &mut writer)
    }
}
