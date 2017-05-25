use std::os::unix::io::RawFd;
use std::os::raw::c_int;
use std::io;
use std::ptr;
use libbpf_sys;

use bpf;

/// A BPF prog
#[derive(Debug)]
pub struct Prog {
    fd: RawFd,
}

#[derive(Debug)]
pub struct TestResult {
    data: Vec<u8>,
    retval: u32,
    duration: u32,
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
    pub fn from_rawfd(fd: RawFd) -> Prog {
        Prog {
            fd: fd
        }
    }

    #[cfg(kernelv412)]
    pub fn test_run(&self, repeat: c_int, data: &[u8]) -> io::Result<TestResult> {
        unsafe {
            let mut result = TestResult::default();
            let res = libbpf_sys::bpf_prog_test_run(self.fd,
                                                    repeat,
                                                    data.as_ptr() as *mut _,
                                                    data.len() as u32,
                                                    ptr::null_mut(),
                                                    ptr::null_mut(),
                                                    &mut result.retval as *mut _,
                                                    &mut result.duration as *mut _);
            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(TestResult::default())
        }
    }
}
