fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let def_path = std::path::Path::new(&manifest_dir).join("termwrap.def");
        println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
    }
    println!("cargo:rerun-if-changed=termwrap.def");
}
