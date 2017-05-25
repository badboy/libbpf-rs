use libc;
use libbpf_sys;

use std::os::unix::io::RawFd;
use std::os::raw::c_uint;
use std::ffi::CString;
use std::io;
use std::ptr;

use utils::*;

/// Types of a eBPF program
///
/// These are kept in sync with prog types available in the kernel.
/// Newer types are only available on newer kernels.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ProgType {
    Unspec          = 0,
    SocketFilter    = 1,
    Kprobe          = 2,
    SchedCls        = 3,
    SchedAct        = 4,
    Tracepoint      = 5,
    XDP             = 6,
    PerfEvent       = 7,
    CgroupSkb       = 8,
    CgroupSock      = 9,
    LwtIn           = 10,
    LwtOut          = 11,
    LwtXmit         = 12,
}

impl ProgType {
    fn as_bpf_prog_type(&self) -> libbpf_sys::bpf_prog_type {
        use self::ProgType::*;
        use libbpf_sys::bpf_prog_type::*;

        match *self {
            Unspec          => BPF_PROG_TYPE_UNSPEC,
            SocketFilter    => BPF_PROG_TYPE_SOCKET_FILTER,
            Kprobe          => BPF_PROG_TYPE_KPROBE,
            SchedCls        => BPF_PROG_TYPE_SCHED_CLS,
            SchedAct        => BPF_PROG_TYPE_SCHED_ACT,
            Tracepoint      => BPF_PROG_TYPE_TRACEPOINT,
            XDP             => BPF_PROG_TYPE_XDP,
            PerfEvent       => BPF_PROG_TYPE_PERF_EVENT,
            CgroupSkb       => BPF_PROG_TYPE_CGROUP_SKB,
            CgroupSock      => BPF_PROG_TYPE_CGROUP_SOCK,
            LwtIn           => BPF_PROG_TYPE_LWT_IN,
            LwtOut          => BPF_PROG_TYPE_LWT_OUT,
            LwtXmit         => BPF_PROG_TYPE_LWT_XMIT,
        }
    }
}

/// When attached to cgroups, a eBPF prog can act on ingress, egress or socket creation.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AttachType {
    CgroupInetIngress = 0,
    CgroupInetEgress  = 1,
    CgroupInetSockCreate = 2,
}

impl AttachType {
    fn as_bpf_attach_type(&self) -> libbpf_sys::bpf_attach_type {
        use self::AttachType::*;
        use libbpf_sys::bpf_attach_type::*;

        match *self {
            CgroupInetIngress => BPF_CGROUP_INET_EGRESS,
            CgroupInetEgress  => BPF_CGROUP_INET_EGRESS,
            CgroupInetSockCreate => BPF_CGROUP_INET_SOCK_CREATE,
        }
    }
}

/// A loaded eBPF program.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prog {
    fd: RawFd,
}

/// Results from a eBPF test run.
#[derive(Debug)]
pub struct TestResult {
    /// Contains the (possibly modified) context object.
    pub data: Vec<u8>,
    /// Represents the return value of the eBPF program. Its meaning depends on the type of.
    pub retval: u32,
    /// Time it took to run the test.
    pub duration: u32,
}

impl Default for TestResult {
    fn default() -> TestResult {
        TestResult {
            data: Vec::new(),
            retval: 0,
            duration: 0,
        }
    }
}

impl Prog {
    /// Load a eBPF program into the kernel
    ///
    /// * `typ`: Specify the type of the program. Different types have access to different helper
    ///   functions and get a different type of context object when invoked.
    /// * `insns` are the raw eBPF bytecode instructions of the program.
    /// * `license`: The kernel requires a license for every loaded program. Certain functionality
    ///   is disabled for non-GPL programs.
    pub fn load(typ: ProgType, insns: &[u8], license: &str) -> io::Result<Prog> {
        const INSN_SIZE : usize = 8;
        assert!(insns.len() % INSN_SIZE == 0);

        let license = CString::new(license).unwrap();
        let insns_cnt = insns.len() / INSN_SIZE;

        unsafe {
            val_check(libbpf_sys::bpf_load_program(
                    typ.as_bpf_prog_type(),
                    insns.as_ptr() as *const _,
                    insns_cnt,
                    license.as_ptr(),
                    libbpf_sys::KERNEL_VERSION,
                    ptr::null_mut(),
                    0))
                .map(|fd| Prog { fd })
        }
    }

    #[cfg(kernelv412)]
    pub fn verify(typ: ProgType, insns: &[u8], license: &str, strict_alignment: bool) -> io::Result<Prog> {
        const INSN_SIZE : usize = 8;
        assert!(insns.len() % INSN_SIZE == 0);

        let license = CString::new(license).unwrap();
        let insns_cnt = insns.len() / INSN_SIZE;

        unsafe {
            val_check(libbpf_sys::bpf_verify_program(
                    typ.as_bpf_prog_type(),
                    insns.as_ptr() as *const _,
                    insns_cnt,
                    if strict_alignment { 1 } else { 0 },
                    license.as_ptr(),
                    libbpf_sys::KERNEL_VERSION,
                    ptr::null_mut(),
                    0))
                .map(|fd| Prog { fd })
        }
    }

    /// Get a `Prog` object form a raw file descriptor.
    ///
    /// No checks on the validity of this file descriptor are performed.
    pub unsafe fn from_rawfd(fd: RawFd) -> Prog {
        Prog {
            fd: fd
        }
    }

    /// Attach this eBPF prog to the specified cgroup, identified by a file descriptor.
    pub fn attach(&self, attachable_fd: RawFd, typ: AttachType, flags: c_uint) -> io::Result<()> {
        unsafe {
            err_check(libbpf_sys::bpf_prog_attach(
                    self.fd,
                    attachable_fd,
                    typ.as_bpf_attach_type(),
                    flags))
        }
    }

    /// Deattach this eBPF prog from the specified cgroup, identified by a file descriptor.
    pub fn deattach(&self, attachable_fd: RawFd, typ: AttachType) -> io::Result<()> {
        unsafe {
            err_check(libbpf_sys::bpf_prog_detach(attachable_fd, typ.as_bpf_attach_type()))
        }
    }

    #[cfg(kernelv412)]
    /// Run the loaded eBPF program several times for testing.
    ///
    /// Specify the number of iterations the eBPF prog should be run in the kernel.
    pub fn test_run(&self, repeat: c_int, data: &[u8]) -> io::Result<TestResult> {
        unsafe {
            let mut result = TestResult::default();
            let res = err_check(libbpf_sys::bpf_prog_test_run(self.fd,
                                                    repeat,
                                                    data.as_ptr() as *mut _,
                                                    data.len() as u32,
                                                    ptr::null_mut(),
                                                    ptr::null_mut(),
                                                    &mut result.retval as *mut _,
                                                    &mut result.duration as *mut _))?;

            Ok(result)
        }
    }

    /// Persist an eBPF prog to a special filesystem.
    ///
    /// Usually the eBPF filesystem is exposed under `/sys/fs/bpf`.
    /// You can mount this filesystem using:
    ///
    /// ```text
    /// mount -t bpf none /sys/fs/bpf
    /// ```
    pub fn pin(&self, pathname: &str) -> io::Result<()> {
        let cstr = CString::new(pathname).unwrap();

        unsafe {
            err_check(libbpf_sys::bpf_obj_pin(self.fd, cstr.as_ptr()))
        }
    }

    /// Load prog information from a path to a persisted eBPF prog.
    ///
    /// Returns an IO error if anything goes wrong.
    pub fn from_path(pathname: &str) -> io::Result<Prog> {
        let cstr = CString::new(pathname).unwrap();

        unsafe {
            val_check(libbpf_sys::bpf_obj_get(cstr.as_ptr()))
                .map(|fd| Prog { fd })
        }
    }
}

impl Drop for Prog {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_prog() {
        let prog = [
            0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];

        Prog::load(ProgType::SocketFilter, &prog, "GPL").unwrap();
    }
}
