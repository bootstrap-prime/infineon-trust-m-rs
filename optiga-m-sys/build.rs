use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let rustbindings = out_dir.clone().join("rustbindings.h");

    let io_bindings = cbindgen::Builder::new();

    io_bindings
        .with_language(cbindgen::Language::C)
        .with_crate(crate_dir)
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
        .files(
            walkdir::WalkDir::new("optiga-m")
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|e| !e.file_type().is_dir())
                .map(|file| file.into_path()),
        )
        .compile("optiga-m.o");

    // I guess you don't need to include everything?
    // these stolen from
    // https://github.com/Infineon/optiga-trust-m/wiki/Initialisation-hints
    // builder = builder
    //     // .file("optiga-m/optiga_cmd.c")
    //     .file("optiga-m/optiga_util.c")
    //     // .file("optiga-m/pal_os_event.c")
    //     .file("optiga-m/pal.c")
    //     .file("optiga-m/pal_os_timer.c");

    // for file in
    // {
    //     builder = builder.file(file.path());
    // }

    // builder

    let bindings = bindgen::Builder::default()
        .header("optiga-m/optiga_util.h")
        .header("optiga-m/pal_os_event.h")
        .header("optiga-m/pal.h")
        .header("optiga-m/pal_os_timer.h")
        .header("optiga-m/optiga_crypt.h")
        .header("optiga-m/optiga_cmd.h")
        .header(rustbindings.to_str().unwrap())
        .clang_arg(format!("--target={}", target))
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

    println!("cargo:rustc-link-lib=optiga-m.o");

    Ok(())
}
