use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let rustbindings = out_dir.clone().join("rustbindings.h");

    let io_bindings = cbindgen::Builder::new();

    io_bindings
        .with_language(cbindgen::Language::C)
        .with_crate(&crate_dir)
        .with_include(
            crate_dir
                .clone()
                .join("optiga-m/pal_os_event.h")
                .into_os_string()
                .into_string()
                .unwrap(),
        )
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&rustbindings);

    let target = env::var("TARGET")?;
    let mut builder = cc::Build::new();

    let _builder = builder
        .flag("-std=c11")
        .flag("-Wno-unused")
        .flag("-Wno-cast-function-type")
        .flag("-Wno-missing-field-initializers")
        .flag("-Werror-implicit-function-declaration")
        .include(&out_dir)
        .include("optiga-m")
        .static_flag(true)
        // .define("OPTIGA_CRYPT_HASH_ENABLED", None)
        .files(
            walkdir::WalkDir::new("optiga-m")
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|e| !e.file_type().is_dir())
                .map(|file| file.into_path())
                .filter(|e| {
                    // Option<String> -> Option<bool> -> bool
                    e.extension().map(|e| e == "c").unwrap_or_default()
                }),
        )
        .compile("optiga-m-sys");

    let bindings = bindgen::Builder::default()
        .header("optiga-m/optiga_util.h")
        .header("optiga-m/pal_os_event.h")
        .header("optiga-m/pal.h")
        .header("optiga-m/pal_os_timer.h")
        .header("optiga-m/optiga_crypt.h")
        .header("optiga-m/optiga_cmd.h")
        .clang_arg(format!("--target={}", target))
        .detect_include_paths(true)
        .layout_tests(false)
        .use_core()
        .ctypes_prefix("cty")
        .rustfmt_bindings(true)
        .fit_macro_constants(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
