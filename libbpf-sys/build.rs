extern crate gcc;

fn kernel_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 16) + (b << 8) + c
}

fn get_kernel_version() -> u32 {
    let expanded = gcc::Config::new()
                .file("src/version.h")
                .expand();
    let expanded_str = String::from_utf8(expanded)
        .expect("Need a valid string in src/version.h");
    let version_str = expanded_str.lines().last().expect("No version line found");
    let version : u32 = str::parse(version_str).expect("No valid kernel version number found");

    version
}

fn main() {
    let kernel_ver = get_kernel_version();

    if kernel_ver >= kernel_version(4,12,0) {
        println!("cargo:rustc-cfg=kernelv412");
    }

    gcc::compile_library("libbpf.a", &["src/bpf.c"]);
}
