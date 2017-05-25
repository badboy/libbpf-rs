extern crate gcc;

use std::env;
use std::path::Path;
use std::fs::File;
use std::io::Write;

fn kernel_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 16) + (b << 8) + c
}

fn get_kernel_version() -> u32 {
    let version_str = if let Ok(var) = env::var("KERNEL_VERSION") {
        var
    } else {
        let expanded = gcc::Config::new()
            .file("src/version.h")
            .expand();
        let expanded_str = String::from_utf8(expanded)
            .expect("Need a valid string in src/version.h");
        expanded_str.lines().last().expect("No version line found").to_string()
    };
    let version : u32 = str::parse(&version_str).expect("No valid kernel version number found");

    version
}

fn write_kernel_version(ver: u32) {
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("version.rs");
    let mut file = File::create(path).unwrap();
    writeln!(file, "pub const KERNEL_VERSION : u32 = {};", ver).unwrap();
}

fn main() {
    let kernel_ver = get_kernel_version();
    println!("cargo:rustc-env=KERNEL_VERSION={}", kernel_ver);
    write_kernel_version(kernel_ver);

    if kernel_ver >= kernel_version(4,12,0) {
        println!("cargo:rustc-cfg=kernelv412");
    }

    gcc::compile_library("libbpf.a", &["src/bpf.c"]);
}
