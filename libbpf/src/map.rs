use libc;
use libbpf_sys;

use std::os::unix::io::RawFd;
use std::os::raw::{c_int, c_uint};
use std::default::Default;
use std::convert::From;
use std::fmt::{self, Display};
use std::fs::File;
use std::ffi::CString;
use std::io;
use std::io::prelude::*;
use std::iter::Iterator;
use std::iter::IntoIterator;
use std::ptr;

use utils::*;
use bpf;

/// Possible types for BPF maps.
///
/// This must be kept in sync with map types available in the kernel.
///
/// Certain map types do not expose functionality to lookup elements or iterate through keys.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MapType {
    Unspec,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCPUHash,
    PerCPUArray,
    StackTrace,
    CgroupArray,
    LRUHash,
    LRUPerCPUHash,
    LPMTrie,
    ArrayOfMaps,
    HashOfMaps,
}

impl MapType {
    fn as_bpf_map_type(&self) -> libbpf_sys::bpf_map_type {
        use self::MapType::*;
        use libbpf_sys::bpf_map_type::*;

        match *self {
            Unspec             => BPF_MAP_TYPE_UNSPEC,
            Hash               => BPF_MAP_TYPE_HASH,
            Array              => BPF_MAP_TYPE_ARRAY,
            ProgArray          => BPF_MAP_TYPE_PROG_ARRAY,
            PerfEventArray     => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            PerCPUHash         => BPF_MAP_TYPE_PERCPU_HASH,
            PerCPUArray        => BPF_MAP_TYPE_PERCPU_ARRAY,
            StackTrace         => BPF_MAP_TYPE_STACK_TRACE,
            CgroupArray        => BPF_MAP_TYPE_CGROUP_ARRAY,
            LRUHash            => BPF_MAP_TYPE_LRU_HASH,
            LRUPerCPUHash      => BPF_MAP_TYPE_LRU_PERCPU_HASH,
            LPMTrie            => BPF_MAP_TYPE_LPM_TRIE,
            ArrayOfMaps        => BPF_MAP_TYPE_ARRAY_OF_MAPS,
            HashOfMaps         => BPF_MAP_TYPE_HASH_OF_MAPS,
        }
    }
}

/// A loaded eBPF map
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Map {
    /// The file descriptor of the map
    fd: RawFd,
    /// Type of the map
    map_type: MapType,
    /// Size of keys in the map, in bytes
    key_size: usize,
    /// Size of values in the map, in bytes
    value_size: usize,
    /// The maximum number of entries this map can hold
    max_entries: usize,
    /// Additional flags set at creation
    flags: usize,
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub struct MapIterator<'a> {
    map: &'a Map,
    key: Vec<u8>,
}

impl From<u8> for MapType {
    fn from(val: u8) -> MapType {
        use self::MapType::*;

        match val {
            0 => Unspec,
            1 => Hash,
            2 => Array,
            3 => ProgArray,
            4 => PerfEventArray,
            5 => PerCPUHash,
            6 => PerCPUArray,
            7 => StackTrace,
            8 => CgroupArray,
            9 => LRUHash,
            10 => LRUPerCPUHash,
            11 => LPMTrie,
            _ => panic!("Invalid map type number"),
        }
    }
}

impl Default for Map {
    fn default() -> Map {
        Map {
            fd: 0,
            map_type: MapType::Unspec,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            flags: 0,
        }
    }
}

impl Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Type:          {:?}\n", self.map_type)?;
        write!(f, "Key size:      {:?}\n", self.key_size)?;
        write!(f, "Value size:    {:?}\n", self.value_size)?;
        write!(f, "Max entries:   {:?}", self.max_entries)
    }
}

impl Map {
    /// Load map information from a path to a persisted BPF map
    ///
    /// Returns an IO error if anything goes wrong.
    pub fn from_path(pathname: &str) -> io::Result<Map> {
        let fd = bpf::obj_get_fd(pathname)?;

        let fdinfo = format!("/proc/self/fdinfo/{}", fd);
        let mut infofile = File::open(fdinfo)?;

        let mut buf = String::new();
        infofile.read_to_string(&mut buf)?;

        let mut m = Map::default();
        m.fd = fd;

        for line in buf.lines() {
            let vals = line.split('\t').collect::<Vec<_>>();
            assert_eq!(2, vals.len());

            let key = &vals[0];
            let val = &vals[1];

            match *key {
                "map_type:" => m.map_type = val.parse::<u8>().map(|v| MapType::from(v)).unwrap(),
                "key_size:" => m.key_size = val.parse::<usize>().unwrap(),
                "value_size:" => m.value_size = val.parse::<usize>().unwrap(),
                "max_entries:" => m.max_entries = val.parse::<usize>().unwrap(),
                "map_flags:" => m.flags = usize::from_str_radix(&val[2..], 16).unwrap(),
                _ => {}
            }
        }

        Ok(m)
    }

    pub fn create(typ: MapType, key_size: usize, value_size: usize, max_entries: usize) -> io::Result<Map> {
        unsafe {
            let flags = 0;
            let fd = val_check(libbpf_sys::bpf_create_map(typ.as_bpf_map_type(),
                                                 key_size as c_int,
                                                 value_size as c_int,
                                                 max_entries as c_int,
                                                 flags as c_uint))?;

            Ok(Map {
                fd: fd,
                map_type: typ,
                key_size: key_size,
                value_size: value_size,
                max_entries: max_entries,
                flags: flags
            })
        }
    }

    pub fn lookup(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        assert!(key.len() == self.key_size);

        bpf::lookup_elem(self.fd, key, self.value_size)
    }

    pub fn insert(&self, key: &[u8], value: &[u8]) -> io::Result<()> {
        assert!(key.len() == self.key_size);
        assert!(value.len() == self.value_size);

        bpf::update_elem(self.fd, key, value, 0)
    }

    pub fn delete(&self, key: &[u8]) -> io::Result<()> {
        assert!(key.len() == self.key_size);

        bpf::delete_elem(self.fd, key)
    }

    pub fn get_next_key(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        assert!(key.len() == self.key_size);

        bpf::get_next_key(self.fd, key, self.key_size)
    }

    pub fn pin(&self, pathname: &str) -> io::Result<()> {
        let cstr = CString::new(pathname).unwrap();

        unsafe {
            err_check(libbpf_sys::bpf_obj_pin(self.fd, cstr.as_ptr()))
        }
    }
}

impl<'a> IntoIterator for &'a Map {
    type Item = (Vec<u8>, Vec<u8>);
    type IntoIter = MapIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let key = vec![0; self.key_size];
        MapIterator {
            map: self,
            key: key,
        }
    }
}

impl<'a> Iterator for MapIterator<'a> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let next_key = match self.map.get_next_key(&self.key) {
            Ok(key) => key,
            Err(_) => return None,
        };
        let value = match self.map.lookup(&next_key) {
            Ok(val) => val,
            Err(_) => return None,
        };

        unsafe {
            ptr::copy_nonoverlapping(next_key.as_ptr(), self.key.as_mut_ptr(), self.map.key_size);
        }

        Some((next_key, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn create_map() {
        Map::create(MapType::Hash,
                    mem::size_of::<u32>(),
                    mem::size_of::<u32>(),
                    32).unwrap();
    }

    #[test]
    fn add_to_map() {
        let map = Map::create(MapType::Hash,
                    mem::size_of::<u32>(),
                    mem::size_of::<u32>(),
                    32).unwrap();

        let key = [1,2,3,4];
        assert!(map.lookup(&key).is_err());
        let value = [42,42,42,42];
        map.insert(&key, &value).unwrap();
    }

    #[test]
    fn lookup_in_map() {
        let map = Map::create(MapType::Hash,
                    mem::size_of::<u32>(),
                    mem::size_of::<u32>(),
                    32).unwrap();

        let key = [1,2,3,4];
        let value = [42,42,42,42];
        map.insert(&key, &value).unwrap();

        assert_eq!(map.lookup(&key).unwrap(), &value[..]);
    }

    #[test]
    fn iterate() {
        let map = Map::create(MapType::Hash,
                    mem::size_of::<u32>(),
                    mem::size_of::<u32>(),
                    32).unwrap();

        let mut key = [1,0,0,0];
        let value = [42,42,42,42];

        let mut expected_sum = 0;
        for i in 1..5 {
            expected_sum += i;
            key[0] = i;
            map.insert(&key, &value).unwrap();
        }

        let mut sum = 0;
        for (key, val) in &map {
            sum += key[0];
            assert_eq!(0, key[1]);
            assert_eq!(val, value);
        }

        assert_eq!(expected_sum, sum);
    }
}
