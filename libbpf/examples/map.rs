extern crate libbpf;

use std::mem;
use libbpf::{Map, MapType};

fn main() {
    let map = Map::create(MapType::Hash,
                          mem::size_of::<u32>(),
                          mem::size_of::<u32>(),
                          32).unwrap();

    let key = [1,2,3,4];

    // No key in the map for now
    assert!(map.lookup(&key).is_err());

    let value = [42,42,42,42];
    map.insert(&key, &value).unwrap();

    // After inserting, we can look it up
    assert_eq!(map.lookup(&key).unwrap(), &value[..]);

    // We can iterate all key/value pairs
    for (key, val) in &map {
        println!("{:?} => {:?}", key, val);
    }

    // ...and delete stuff again
    map.delete(&key).unwrap();
    assert!(map.lookup(&key).is_err());
}
