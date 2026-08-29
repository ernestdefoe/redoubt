//! Stamp the Windows resources onto `redoubt.exe`.
//!
//! Without this the binary has a blank icon and no version tab, which is the
//! first thing anyone checks before trusting a security tool with
//! administrator rights. The description is what Windows shows in the UAC
//! prompt and in Task Manager, so it is written for a person to read rather
//! than as a crate name.

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }

    let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../brand/redoubt.ico")
        .canonicalize();

    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "Redoubt")
        .set("FileDescription", "Redoubt Antivirus")
        .set("CompanyName", "Ernest Defoe")
        .set("LegalCopyright", "Copyright (c) 2026 Ernest Defoe")
        .set("OriginalFilename", "redoubt.exe");

    // Built from source without the brand directory, the binary should still
    // build - it just goes out plain.
    if let Ok(p) = &icon {
        res.set_icon(&p.to_string_lossy());
        println!("cargo:rerun-if-changed={}", p.display());
    }

    if let Err(e) = res.compile() {
        // Not fatal: a missing resource compiler costs an icon, not a build.
        println!("cargo:warning=could not stamp Windows resources: {e}");
    }
}
