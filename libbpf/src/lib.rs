extern crate libbpf_sys;

mod bpf;

pub mod map;
pub mod prog;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
