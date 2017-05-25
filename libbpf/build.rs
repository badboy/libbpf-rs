use std::env;

fn kernel_env(maj: u32, min: u32) {
    let var = format!("DEP_LIBBPF_KERNELV{}{}", maj, min);
    if let Ok(_) = env::var(var) {
        println!("cargo:rustc-cfg=kernelv{}{}", maj, min);
    }
}

fn main() {
    kernel_env(4,12);
}
