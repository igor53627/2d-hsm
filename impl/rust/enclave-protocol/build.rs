fn main() {
    println!("cargo::rustc-check-cfg=cfg(release_build)");
    // Key-safety compile_error!s apply when building a non-debug artifact (release profile,
    // custom optimized profile, or TWOD_HSM_STRICT_RELEASE_GUARDS from nix prod enclave).
    let profile = std::env::var("PROFILE").unwrap_or_default();
    // Build scripts see OPT_LEVEL, not CARGO_CFG_OPT_LEVEL (that is for the crate target only).
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_default();
    let strict = std::env::var_os("TWOD_HSM_STRICT_RELEASE_GUARDS").is_some();
    let release_profile = profile == "release";
    let release_like = profile != "debug"
        && profile != "test"
        && (opt_level == "3" || opt_level == "s" || opt_level == "z");
    if release_profile || strict || release_like {
        println!("cargo:rustc-cfg=release_build");
    }
}
