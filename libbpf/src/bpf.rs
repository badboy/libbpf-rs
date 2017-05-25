use std::os::unix::io::RawFd;
use std::os::raw::c_int;
use std::ffi::CString;
use std::io;

use utils::*;
use libbpf_sys::*;

/// Lookup an element from the map
pub fn lookup_elem(fd: c_int, key: &[u8], value_size: usize) -> io::Result<Vec<u8>> {
    unsafe {
        let mut value : Vec<u8> = Vec::with_capacity(value_size);

        err_check(bpf_map_lookup_elem(fd,
                                      key.as_ptr() as *const _,
                                      value.as_mut_ptr() as *mut _))?;
        value.set_len(value_size);
        Ok(value)
    }
}

/// Lookup an element from the map
pub fn update_elem(fd: c_int, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
    unsafe {
        err_check(bpf_map_update_elem(fd,
                                      key.as_ptr() as *const _,
                                      value.as_ptr() as *const _,
                                      flags))
    }
}
/// Delete an element from the map
pub fn delete_elem(fd: c_int, key: &[u8]) -> io::Result<()> {
    unsafe {
        err_check(bpf_map_delete_elem(fd, key.as_ptr() as *const _))
    }
}

/// Iterate to the next key from a given one in a map
///
/// ## Panics
///
/// Panics if the map is invalid or the passed key is not of the expected length.
pub fn get_next_key(fd: c_int, old_key: &[u8], key_size: usize) -> io::Result<Vec<u8>> {
    unsafe {
        let mut next_key : Vec<u8> = Vec::with_capacity(key_size);

        err_check(bpf_map_get_next_key(fd,
                                       old_key.as_ptr() as *const _,
                                       next_key.as_mut_ptr() as *mut _))?;

        next_key.set_len(key_size);
        Ok(next_key)
    }
}

/// Get a file descriptor from a path to a persisted BPF map
pub fn obj_get_fd(pathname: &str) -> io::Result<RawFd> {
    let cstr = CString::new(pathname).unwrap();

    unsafe {
        val_check(bpf_obj_get(cstr.as_ptr()))
    }
}
