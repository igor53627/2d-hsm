fn main() {
    println!("cargo::rustc-check-cfg=cfg(release_build)");
    // Key-safety compile_error!s apply for any non-dev Cargo profile (release, bench, custom
    // optimized profiles such as [profile.dist]). Nix prod enclave sets TWOD_HSM_STRICT_RELEASE_GUARDS=1
    // as belt-and-suspenders when PROFILE semantics are ambiguous.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let strict = std::env::var_os("TWOD_HSM_STRICT_RELEASE_GUARDS").is_some();
    let release_like = profile != "debug" && profile != "test";
    if strict || release_like {
        println!("cargo:rustc-cfg=release_build");
    }
}
