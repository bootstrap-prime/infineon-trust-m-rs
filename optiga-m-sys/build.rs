use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let rustbindings = out_dir.join("rustbindings.h");
    let target = env::var("TARGET")?;

    let bindings = bindgen::Builder::default()
        .header("optiga-trust-m/optiga/include/optiga/optiga_util.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal_os_event.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal_os_timer.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal_i2c.h")
        .header("optiga-trust-m/optiga/include/optiga/optiga_crypt.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal_logger.h")
        .header("optiga-trust-m/optiga/include/optiga/pal/pal_gpio.h")
        .clang_arg(format!("--target={}", target))
        .clang_arg("-Ioptiga-trust-m/optiga/include/")
        .detect_include_paths(true)
        .layout_tests(false)
        .use_core()
        .ctypes_prefix("cty")
        .rustfmt_bindings(true)
        .fit_macro_constants(true)
        .allowlist_var(".*OPTIGA.*")
        .allowlist_var(".*optiga.*")
        .allowlist_var(".*PAL.*")
        .allowlist_type(".*pal_.*")
        .allowlist_type(".*optiga.*")
        .allowlist_type("data_blob")
        .allowlist_type(".*upper_layer_callback_t")
        .allowlist_function(".*optiga_.*")
        .allowlist_function(".*pal_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let io_bindings = cbindgen::Builder::new();

    io_bindings
        .with_language(cbindgen::Language::C)
        .with_crate(&crate_dir)
        .with_include("optiga/pal/pal.h")
        .with_include("optiga/pal/pal_gpio.h")
        .with_include("optiga/pal/pal_i2c.h")
        .with_include("optiga/pal/pal_logger.h")
        .with_include("optiga/pal/pal_os_timer.h")
        .with_include("optiga/pal/pal_os_event.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&rustbindings);

    let mut builder = cc::Build::new();

    let _builder = builder
        .flag("-std=c11")
        .flag("-Wno-unused")
        .flag("-Wno-cast-function-type")
        .flag("-Wno-missing-field-initializers")
        .flag("-Werror-implicit-function-declaration")
        .flag("-w")
        .include(&out_dir)
        .include("pal")
        .include("optiga-trust-m/optiga/include/")
        .include("optiga-trust-m/optiga/include/optiga/pal")
        .include("pal/optiga/include/optiga/pal")
        .include("printf")
        .file("printf/printf.c")
        .file("pal/pal_os_lock.c")
        .file("pal/pal_configures.c")
        .file("pal/pal_os_datastore.c")
        .file("pal/pal_string.c")
        .define("OPTIGA_LIB_EXTERNAL", "\"optiga_lib_config_external.h\"")
        .files(
            walkdir::WalkDir::new("optiga-trust-m/optiga/")
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|e| !e.file_type().is_dir())
                .map(|file| file.into_path())
                .filter(|e| {
                    // Option<String> -> Option<bool> -> bool
                    e.extension().map(|e| e == "c").unwrap_or_default()
                })
                .filter(|e| {
                    e.file_name().unwrap() != "pal_os_memory.h"
                        && e.file_name().unwrap() != "pal_crypt_mbedtls.c"
                }),
        )
        .compile("optiga-m-sys");

    println!("rerun-if-changed=./optiga-trust-m");

    Ok(())
}
