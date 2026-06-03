fn main() {
    println!("cargo::rustc-check-cfg=cfg(release_build)");
    // PROFILE is set by Cargo for all build scripts (debug / release / …).
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=release_build");
    }
}