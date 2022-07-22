#![no_main]
use libfuzzer_sys::fuzz_target;

use etherparse::SlicedPacket;

fuzz_target!(|data: &[u8]| {
    let _ = SlicedPacket::from_ethernet(data);
    let _ = SlicedPacket::from_ip(data);

    if data.len() > 2 {
        let ether_type = u16::from_be_bytes([data[0], data[1]]);
        let data = &data[2..];
        let _ = SlicedPacket::from_ether_type(ether_type, data);
    }
});
