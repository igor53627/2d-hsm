fn main() {
    println!("cargo::rustc-check-cfg=cfg(release_build)");
    // Key-safety compile_error!s apply for release builds. Nix prod enclave may set
    // TWOD_HSM_STRICT_RELEASE_GUARDS=1 as belt-and-suspenders.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let strict = std::env::var_os("TWOD_HSM_STRICT_RELEASE_GUARDS").is_some();
    let release_like = profile == "release";
    if strict || release_like {
        println!("cargo:rustc-cfg=release_build");
    }
}
