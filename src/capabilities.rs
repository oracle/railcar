use caps::*;
use oci::LinuxCapabilityType;

fn to_cap(cap: LinuxCapabilityType) -> Capability {
    unsafe { ::std::mem::transmute(cap) }
}

const ALL_CAP_SETS: &'static [CapSet] = &[
    CapSet::Effective,
    CapSet::Permitted,
    CapSet::Inheritable,
    CapSet::Ambient,
];

pub fn reset_effective() -> ::Result<()> {
    let mut all = CapsHashSet::new();
    for c in Capability::iter_variants() {
        all.insert(c);
    }
    set(None, CapSet::Effective, all)?;
    Ok(())
}

pub fn drop_privileges(cs: &[LinuxCapabilityType]) -> ::Result<()> {
    let mut all = CapsHashSet::new();
    for c in Capability::iter_variants() {
        all.insert(c);
    }
    let mut capabilities = CapsHashSet::new();
    for c in cs {
        capabilities.insert(to_cap(*c));
    }
    // drop excluded caps from the bounding set
    for c in all.difference(&capabilities) {
        drop(None, CapSet::Bounding, *c)?;
    }
    // set all sets for current process
    for capset in ALL_CAP_SETS {
        set(None, *capset, capabilities.clone())?;
    }
    Ok(())
}
