//! # libbpf - A convenient wrapper around the eBPF kernel API
//!
//! eBPF stands for Extended Berkeley Packet Filter.
//! eBPF is a in-kernel virtual machine, which allows to safely execute user supplied programs in
//! the kernel.
//!
//! Programs can be loaded into the kernel using a syscall.
//! In addition, data with programs can be shared through BPF maps.
//! These are also managed from the user side via a syscall.
//!
//! `libbpf` offers a convenient wrapper around these syscalls.

extern crate libc;
extern crate libbpf_sys;

mod bpf;
mod utils;

mod map;
mod prog;

pub use map::{
    Map,
    MapType,
    MapIterator
};

pub use prog::{
    Prog,
    ProgType,
    TestResult,
    AttachType
};
