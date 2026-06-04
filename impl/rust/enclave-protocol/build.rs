fn main() {
    println!("cargo::rustc-check-cfg=cfg(release_build)");
    // PROFILE is set by Cargo for all build scripts (debug / release / …).
    // Custom cargo profiles do not set PROFILE=release; use TWOD_HSM_STRICT_RELEASE_GUARDS=1
    // on production enclave builds (see impl/nix/vm-hsm/enclave.nix).
    let strict = std::env::var_os("TWOD_HSM_STRICT_RELEASE_GUARDS").is_some();
    if std::env::var("PROFILE").as_deref() == Ok("release") || strict {
        println!("cargo:rustc-cfg=release_build");
    }
}
