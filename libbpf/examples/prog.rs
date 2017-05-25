//! A simple example showing how to load a BPF program,
//! assembled from instructions.
//!
//! To see any effect:
//!
//! ```
//! echo 2 | sudo tee /proc/sys/net/core/bpf_jit_enable
//! cargo run --example prog
//! dmesg
//! ```
//!
//! You should see the kernel's log showing the JITted code,
//! e.g.:
//!
//! ```
//! flen=5 proglen=90 pass=4 image=ffffffffa000639e from=prog pid=28330
//! JIT code: 00000000: 55 48 89 e5 48 81 ec 28 02 00 00 48 89 9d d8 fd
//! JIT code: 00000010: ff ff 4c 89 ad e0 fd ff ff 4c 89 b5 e8 fd ff ff
//! JIT code: 00000020: 4c 89 bd f0 fd ff ff 31 c0 48 89 85 f8 fd ff ff
//! JIT code: 00000030: 31 c0 bf 02 00 00 00 83 c0 01 01 f8 48 8b 9d d8
//! JIT code: 00000040: fd ff ff 4c 8b ad e0 fd ff ff 4c 8b b5 e8 fd ff
//! JIT code: 00000050: ff 4c 8b bd f0 fd ff ff c9 c3
//! ```

extern crate libbpf;
extern crate rbpf;

use rbpf::assembler::assemble;
use libbpf::{Prog, ProgType};

fn main() {
    let prog = assemble("mov32 r0, 0
                         mov32 r1, 2
                         add32 r0, 1
                         add32 r0, r1
                         exit").unwrap();

    let bpf = Prog::load(ProgType::SocketFilter, &prog, "GPL").unwrap();
    println!("Loaded BPF, fd: {:?}", bpf);

}
