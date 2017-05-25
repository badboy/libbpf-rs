use std::os::unix::io::RawFd;
use std::default::Default;
use std::convert::From;
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::iter::Iterator;
use std::iter::IntoIterator;
use std::ptr;

use bpf;

/// Possible types for BPF maps.
///
/// This must be kept in sync with map types available in the kernel.
///
/// Certain map types do not expose functionality to lookup elements or iterate through keys.
#[derive(Debug)]
#[repr(u8)]
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
    #[cfg(kernelv412)]
    LPMTrie,
}

/// A Map represents metainformation about a BPF map
#[derive(Debug)]
pub struct Map {
    /// The file descriptor of the map
    pub fd: RawFd,
    /// Type of the map
    pub map_type: MapType,
    /// Size of keys in the map, in bytes
    pub key_size: usize,
    /// Size of values in the map, in bytes
    pub value_size: usize,
    /// The maximum number of entries this map can hold
    pub max_entries: usize,
    /// Additional flags set at creation
    pub map_flags: usize,
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
            #[cfg(kernelv412)]
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
            map_flags: 0,
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
        let fd = bpf::obj_get_fd(pathname);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

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
                "map_flags:" => m.map_flags = usize::from_str_radix(&val[2..], 16).unwrap(),
                _ => {}
            }
        }

        Ok(m)
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
