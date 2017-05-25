use std::io;
use std::os::raw::c_int;

pub fn err_check(res: c_int) -> io::Result<()> {
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn val_check(res: c_int) -> io::Result<c_int> {
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(res)
}
