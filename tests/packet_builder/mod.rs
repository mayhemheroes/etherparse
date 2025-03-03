use etherparse::*;
use super::*;

#[test]
fn eth_ipv4_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                  .ipv4([13,14,15,16], [17,18,19,20], 21)
                  .udp(22,23)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    let expected_ip_size: usize = UdpHeader::SERIALIZED_SIZE +
                                  in_payload.len();
    assert_eq!(expected_ip_size
               + Ethernet2Header::SERIALIZED_SIZE
               + Ipv4Header::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: ether_type::IPV4
               });

    //ip header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header::new(
        expected_ip_size as u16,
        21, //ttl
        ip_number::UDP,
        [13,14,15,16],
        [17,18,19,20]
    );
    ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv4_checksum(22, 23, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn ipv4() {
    let auth_ext = IpAuthenticationHeader::new(
        0,
        1,
        2,
        &[3,4,5,6]
    ).unwrap();
    
    //generate
    let in_payload = [22,23,24,25];
    let mut serialized = Vec::new();
    let builder = PacketBuilder::ip(
        IpHeader::Version4(
            Ipv4Header::new(
                in_payload.len() as u16,
                21,
                0,
                [13,14,15,16],
                [17,18,19,20]
            ),
            Ipv4Extensions{
                auth: Some(auth_ext.clone())
            }
        )
    );

    // check size
    assert_eq!(
        builder.size(in_payload.len()),
        Ipv4Header::SERIALIZED_SIZE +
        auth_ext.header_len() +
        in_payload.len()
    );

    // write
    serialized.reserve(builder.size(in_payload.len()));
    builder.write(&mut serialized, 200, &in_payload)
    .unwrap();

    //check the deserialized size
    assert_eq!(
        Ipv4Header::SERIALIZED_SIZE +
        auth_ext.header_len() +
        in_payload.len(),
        serialized.len()
    );

    //deserialize and check that everything is as expected
    use std::io::{Cursor, Read};

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ip header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header::new(
        (auth_ext.header_len() + in_payload.len()) as u16,
        21, //ttl
        ip_number::AUTH, // should have been set
        [13,14,15,16],
        [17,18,19,20]
    );
    ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();
    assert_eq!(ip_actual,
                ip_expected);

    // auth header
    let auth_actual = IpAuthenticationHeader::read(&mut cursor).unwrap();
    assert_eq!(
        auth_actual,
        IpAuthenticationHeader::new(
            200, // ip number should have been set
            1,
            2,
            &[3,4,5,6]
        ).unwrap()
    );

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn ipv6() {
    let auth_ext = IpAuthenticationHeader::new(
        0,
        1,
        2,
        &[3,4,5,6]
    ).unwrap();

    //generate
    let in_payload = [48,49,50,51];
    let mut serialized = Vec::new();
    let builder = PacketBuilder::
        ip(
            IpHeader::Version6(
                Ipv6Header{
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: in_payload.len() as u16,
                    next_header: 0,
                    hop_limit: 47,
                    source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                    destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
                },
                Ipv6Extensions {
                    hop_by_hop_options: None,
                    destination_options: None,
                    routing: None,
                    fragment: None,
                    auth: Some(auth_ext.clone()),
                }
            )
        );

    // check size
    assert_eq!(
        builder.size(in_payload.len()),
        Ipv6Header::SERIALIZED_SIZE +
        auth_ext.header_len() +
        in_payload.len()
    );

    // write
    builder.write(&mut serialized, 200, &in_payload).unwrap();

    //check the deserialized size
    assert_eq!(
        Ipv6Header::SERIALIZED_SIZE +
        auth_ext.header_len() +
        in_payload.len(),
        serialized.len()
    );

    //deserialize and check that everything is as expected
    use std::io::{Cursor, Read};

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 0,
        flow_label: 0,
        payload_length: (auth_ext.header_len() + in_payload.len()) as u16,
        next_header: ip_number::AUTH, // should have been set
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };

    assert_eq!(ip_actual,
               ip_expected);

    // auth header
    let auth_actual = IpAuthenticationHeader::read(&mut cursor).unwrap();
    assert_eq!(
        auth_actual,
        IpAuthenticationHeader::new(
            200, // ip number should have been set
            1,
            2,
            &[3,4,5,6]
        ).unwrap()
    );

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn ipv4_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    PacketBuilder::ipv4([13,14,15,16], [17,18,19,20], 21)
                   .udp(22,23)
                   .write(&mut serialized, &in_payload)
                   .unwrap();

    //check the deserialized size
    let expected_ip_size: usize = UdpHeader::SERIALIZED_SIZE +
                                  in_payload.len();
    assert_eq!(expected_ip_size
               + Ipv4Header::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::{Cursor, Read};

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ip header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header::new(
        expected_ip_size as u16,
        21, //ttl
        ip_number::UDP,
        [13,14,15,16],
        [17,18,19,20]
    );
    ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv4_checksum(22, 23, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn ipv6_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    PacketBuilder::
        ipv6(
             //source
            [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
            //destination
            [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
            //hop_limit
            47,
        )
        .udp(22,23)
        .write(&mut serialized, &in_payload)
        .unwrap();

    //check the deserialized size
    let expected_ip_size: usize = UdpHeader::SERIALIZED_SIZE +
                                  in_payload.len();
    assert_eq!(expected_ip_size
               + Ipv6Header::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::{Cursor, Read};

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 0,
        flow_label: 0,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };

    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(22, 23, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn ipv4_custom_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    PacketBuilder::
        ip(IpHeader::Version4(Ipv4Header::new(
            0, //payload_len will be replaced during write
            12, //time_to_live
            ip_number::TCP, //will be replaced during write
            [13,14,15,16], //source
            [17,18,19,20] //destination
        ), Default::default()))
       .udp(22,23)
       .write(&mut serialized, &in_payload)
       .unwrap();

    //check the deserialized size
    let expected_ip_size: usize = UdpHeader::SERIALIZED_SIZE +
                                  in_payload.len();
    assert_eq!(expected_ip_size
               + Ipv4Header::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::{Cursor, Read};

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ip header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header::new(
        expected_ip_size as u16,
        12, //ttl
        ip_number::UDP,
        [13,14,15,16],
        [17,18,19,20]
    );
    ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv4_checksum(22, 23, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_ipv6_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                        47,
                    )
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE + 
               in_payload.len(),

               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header    
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 0,
        flow_label: 0,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_single_vlan_ipv4_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .single_vlan(0x123)
                  .ipv4([13,14,15,16], [17,18,19,20], 21)
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size

        //check the deserialized size
    let expected_ip_size: usize = UdpHeader::SERIALIZED_SIZE + 
                                  in_payload.len();
    assert_eq!(expected_ip_size + Ethernet2Header::SERIALIZED_SIZE
                                + Ipv4Header::SERIALIZED_SIZE
                                + SingleVlanHeader::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x123,
                    ether_type: ether_type::IPV4
               });

    //ip header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header::new(
        expected_ip_size as u16, //payload_len
        21, //ttl
        ip_number::UDP,
        [13,14,15,16],
        [17,18,19,20]
    );
    ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv4_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_double_vlan_ipv6_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .double_vlan(0x123, 0x234)
                  .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                         47,
                  )
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               DoubleVlanHeader::SERIALIZED_SIZE +
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE + 
               in_payload.len(),
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::ProviderBridging as u16
               });

    //outer vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x123,
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //inner vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x234,
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 0,
        flow_label: 0,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_ip_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .ip(IpHeader::Version6(Ipv6Header{
                        traffic_class: 1,
                        flow_label: 2,
                        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
                        next_header: ip_number::UDP,
                        hop_limit: 47,
                        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
                    }, Default::default()))
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE + 
               in_payload.len(),
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 1,
        flow_label: 2,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_vlan_ip_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .vlan(VlanHeader::Single(SingleVlanHeader{
                      priority_code_point: 1,
                      drop_eligible_indicator: true,
                      vlan_identifier: 0x123,
                      ether_type: 0 //should be overwritten
                  }))
                  .ip(IpHeader::Version6(Ipv6Header{
                        traffic_class: 1,
                        flow_label: 2,
                        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
                        next_header: ip_number::UDP,
                        hop_limit: 47,
                        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
                    }, Default::default()))
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               SingleVlanHeader::SERIALIZED_SIZE +
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE + 
               in_payload.len(),
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;

    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //outer vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 1,
                    drop_eligible_indicator: true,
                    vlan_identifier: 0x123,
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 1,
        flow_label: 2,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

proptest! {
    #[test]
    fn tcp_ipv4(ref input in tcp_any()) {

        //payload
        let in_payload = [24,25,26,27];

        //ip v4 header
        let mut ip_expected = Ipv4Header::new(
            in_payload.len() as u16 + input.header_len(),
            21, //ttl
            ip_number::TCP,
            [13,14,15,16],
            [17,18,19,20]
        );
        ip_expected.header_checksum = ip_expected.calc_header_checksum().unwrap();

        //generated the expected output
        let expected = {
            let mut expected = input.clone();
            //replace urg & ack if the flags are not set
            if !expected.ack {
                expected.acknowledgment_number = 0;
            }
            if !expected.urg {
                expected.urgent_pointer = 0;
            }
            //calculate the checksum
            expected.checksum = expected.calc_checksum_ipv4(&ip_expected, &in_payload[..]).unwrap();
            //done
            expected
        };
        
        //generate
        let serialized = {

            //create builder
            let mut builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                                            .ipv4([13,14,15,16], [17,18,19,20], 21)
                                            .tcp(input.source_port,
                                                 input.destination_port,
                                                 input.sequence_number,
                                                 input.window_size)
                                            .options_raw(input.options()).unwrap();
            //set the flags
            if input.ns {
                builder = builder.ns();
            }
            if input.fin {
                builder = builder.fin();
            }
            if input.syn {
                builder = builder.syn();
            }
            if input.rst {
                builder = builder.rst();
            }
            if input.psh {
                builder = builder.psh();
            }
            if input.ack {
                builder = builder.ack(input.acknowledgment_number);
            }
            if input.urg {
                builder = builder.urg(input.urgent_pointer);
            }
            if input.ece {
                builder = builder.ece();
            }
            if input.cwr {
                builder = builder.cwr();
            }

            let mut serialized = Vec::new();
            builder.write(&mut serialized, &in_payload).unwrap();
            serialized
        };
        
        //deserialize and check that everything is as expected
        use std::io::Cursor;
        use std::io::Read;
        //deserialize each part of the message and check it
        let mut cursor = Cursor::new(&serialized);

        //ethernet 2 header
        assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
                   Ethernet2Header{
                        source: [1,2,3,4,5,6],
                        destination: [7,8,9,10,11,12],
                        ether_type: ether_type::IPV4
                   });

        //ip header
        let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
        assert_eq!(ip_actual,
                   ip_expected);

        //tcp header
        assert_eq!(TcpHeader::read(&mut cursor).unwrap(),
                   expected);

        //payload
        let mut actual_payload: [u8;4] = [0;4];
        cursor.read_exact(&mut actual_payload).unwrap();
        assert_eq!(actual_payload, in_payload);
    }
}

proptest! {
    #[test]
    fn tcp_ipv6(ref input in tcp_any()) {

        //payload
        let in_payload = [24,25,26,27];

        //ip v4 header
        let ip_expected = Ipv6Header{
            traffic_class: 0,
            flow_label: 0,
            payload_length: (input.header_len() as usize + in_payload.len()) as u16,
            next_header: ip_number::TCP,
            hop_limit: 47,
            source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
            destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
        };

        //generated the expected output
        let expected = {
            let mut expected = input.clone();
            //replace urg & ack if the flags are not set
            if !expected.ack {
                expected.acknowledgment_number = 0;
            }
            if !expected.urg {
                expected.urgent_pointer = 0;
            }
            //calculate the checksum
            expected.checksum = expected.calc_checksum_ipv6(&ip_expected, &in_payload[..]).unwrap();
            //done
            expected
        };
        
        //generate
        let serialized = {

            //create builder
            let mut builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                                            .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                                                  [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                                                  47,
                                            )
                                            .tcp(input.source_port,
                                                 input.destination_port,
                                                 input.sequence_number,
                                                 input.window_size)
                                            .options_raw(input.options()).unwrap();
            //set the flags
            if input.ns {
                builder = builder.ns();
            }
            if input.fin {
                builder = builder.fin();
            }
            if input.syn {
                builder = builder.syn();
            }
            if input.rst {
                builder = builder.rst();
            }
            if input.psh {
                builder = builder.psh();
            }
            if input.ack {
                builder = builder.ack(input.acknowledgment_number);
            }
            if input.urg {
                builder = builder.urg(input.urgent_pointer);
            }
            if input.ece {
                builder = builder.ece();
            }
            if input.cwr {
                builder = builder.cwr();
            }

            let mut serialized = Vec::new();
            builder.write(&mut serialized, &in_payload).unwrap();
            serialized
        };
        
        //deserialize and check that everything is as expected
        use std::io::Cursor;
        use std::io::Read;
        //deserialize each part of the message and check it
        let mut cursor = Cursor::new(&serialized);

        //ethernet 2 header
        assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
                   Ethernet2Header{
                        source: [1,2,3,4,5,6],
                        destination: [7,8,9,10,11,12],
                        ether_type: EtherType::Ipv6 as u16
                   });

        //ip header
        let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
        assert_eq!(ip_actual,
                   ip_expected);

        //tcp header
        assert_eq!(TcpHeader::read(&mut cursor).unwrap(),
                   expected);

        //payload
        let mut actual_payload: [u8;4] = [0;4];
        cursor.read_exact(&mut actual_payload).unwrap();
        assert_eq!(actual_payload, in_payload);
    }
}

#[test]
fn tcp_options() {
    let mut serialized = Vec::new();

    use crate::TcpOptionElement::*;
    let options = vec![MaximumSegmentSize(1234), Noop];

    PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
        .ipv4([13,14,15,16], [17,18,19,20], 21)
        .tcp(1,
             2,
             3,
             4)
        .options(&options).unwrap()
        .write(&mut serialized, &[]).unwrap();

    let decoded = PacketHeaders::from_ethernet_slice(&serialized[..]).unwrap();
    let dec_options: Vec<Result<TcpOptionElement, TcpOptionReadError>> = decoded.transport.unwrap().tcp().unwrap().options_iterator().collect();
    assert_eq!(
        &[Ok(MaximumSegmentSize(1234)), Ok(Noop)],
        &dec_options[..]
    );
}

#[test]
fn size() {
    //ipv4 no vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv4Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .ipv4([13,14,15,16], [17,18,19,20], 21)
                             .udp(22,23)
                             .size(123));

    //ipv6 no vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,
               
               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                                   [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                                   47,
                             )
                             .udp(22,23)
                             .size(123));

    //ipv4 single vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               SingleVlanHeader::SERIALIZED_SIZE +
               Ipv4Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .single_vlan(0x123)
                             .ipv4([13,14,15,16], [17,18,19,20], 21)
                             .udp(22,23)
                             .size(123));

    //ipv6 double vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               DoubleVlanHeader::SERIALIZED_SIZE +
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .double_vlan(0x123, 0x234)
                             .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                                   [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                                   47,
                             )
                             .udp(22,23)
                             .size(123));
}

proptest! {
    #[test]
    fn size_tcp(ref input in tcp_any()) {

        assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
                   Ipv4Header::SERIALIZED_SIZE + 
                   input.header_len() as usize +
                   123,

                   PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                                 .ipv4([13,14,15,16], [17,18,19,20], 21)
                                 .tcp(input.source_port, 
                                      input.destination_port, 
                                      input.sequence_number, 
                                      input.window_size)
                                 .options_raw(input.options()).unwrap()
                                 .size(123));
    }
}

proptest! {
    #[test]
    fn ipv4_icmpv4(
        ipv4_source in any::<[u8;4]>(),
        ipv4_dest in any::<[u8;4]>(),
        ipv4_time_to_live in any::<u8>(),
        icmpv4_type_u8 in 15u8..u8::MAX,
        icmpv4_code_u8 in any::<u8>(),
        icmpv4_bytes5to8 in any::<[u8;4]>(),
        icmpv4 in icmpv4_type_any(),
        echo_id in any::<u16>(),
        echo_seq in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test_builder = |builder: PacketBuilderStep<Icmpv4Header>, icmpv4_type: Icmpv4Type| {
            use etherparse::Icmpv4Type::*;
            let adapted_payload = match &icmpv4_type {
                TimestampRequest(_) |
                TimestampReply(_) => &[],
                _ => &payload[..],
            };
            let icmp_expected = Icmpv4Header::with_checksum(icmpv4_type, &adapted_payload);
            let ip_expected = {
                let mut expected_ipv4 = Ipv4Header::new(
                    (icmp_expected.header_len() + adapted_payload.len()) as u16,
                    ipv4_time_to_live,
                    ip_number::ICMP,
                    ipv4_source,
                    ipv4_dest
                );
                expected_ipv4.header_checksum = expected_ipv4.calc_header_checksum().unwrap();
                expected_ipv4
            };

            // test builder.size()
            assert_eq!(
                builder.size(adapted_payload.len()),
                Ethernet2Header::SERIALIZED_SIZE +
                Ipv4Header::SERIALIZED_SIZE +
                icmp_expected.header_len() +
                adapted_payload.len()
            );

            // test builder.write()
            let mut buffer = Vec::<u8>::with_capacity(builder.size(adapted_payload.len()));
            builder.write(&mut buffer, adapted_payload).unwrap();

            // decode packets
            let actual = PacketHeaders::from_ethernet_slice(&buffer).unwrap();

            // check the packets could be decoded
            assert_eq!(
                Some(Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: ether_type::IPV4
                }),
                actual.link
            );
            assert_eq!(
                Some(IpHeader::Version4(ip_expected, Default::default())),
                actual.ip
            );
            assert_eq!(
                Some(TransportHeader::Icmpv4(icmp_expected)),
                actual.transport
            );
            assert_eq!(actual.payload, adapted_payload);
        };

        // icmpv4
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv4(icmpv4.clone());

            test_builder(
                builder,
                icmpv4
            );
        }

        // icmpv4_raw
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv4_raw(icmpv4_type_u8, icmpv4_code_u8, icmpv4_bytes5to8);

            test_builder(
                builder,
                Icmpv4Type::Unknown{
                    type_u8: icmpv4_type_u8,
                    code_u8: icmpv4_code_u8,
                    bytes5to8: icmpv4_bytes5to8,
                }
            );
        }

        // icmpv4_echo_request
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv4_echo_request(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv4Type::EchoRequest(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }

        // icmp4_echo_reply
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv4_echo_reply(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv4Type::EchoReply(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }
    }
}

proptest! {
    #[test]
    fn ipv4_icmpv6(
        ipv4_source in any::<[u8;4]>(),
        ipv4_dest in any::<[u8;4]>(),
        ipv4_time_to_live in any::<u8>(),
        icmpv6_type_u8 in 162u8..u8::MAX,
        icmpv6_code_u8 in any::<u8>(),
        icmpv6_bytes5to8 in any::<[u8;4]>(),
        icmpv6 in icmpv6_type_any(),
        echo_id in any::<u16>(),
        echo_seq in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test_builder = |builder: PacketBuilderStep<Icmpv6Header>, icmpv6_type: Icmpv6Type| {
            // test builder.size()
            assert_eq!(
                builder.size(payload.len()),
                Ethernet2Header::SERIALIZED_SIZE +
                Ipv4Header::SERIALIZED_SIZE +
                icmpv6_type.header_len() +
                payload.len()
            );

            // test builder.write()
            let mut buffer = Vec::<u8>::with_capacity(builder.size(payload.len()));
            // should trigger an error, was it is not possible to calculate the checksum
            assert_matches!(
                builder.write(&mut buffer, &payload),
                Err(_)
            );
        };

        // icmpv6
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv6(icmpv6.clone());

            test_builder(
                builder,
                icmpv6
            );
        }

        // icmpv6_raw
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv6_raw(icmpv6_type_u8, icmpv6_code_u8, icmpv6_bytes5to8);

            test_builder(
                builder,
                Icmpv6Type::Unknown{
                    type_u8: icmpv6_type_u8,
                    code_u8: icmpv6_code_u8,
                    bytes5to8: icmpv6_bytes5to8,
                }
            );
        }

        // icmpv6_echo_request
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv6_echo_request(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv6Type::EchoRequest(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }

        // icmp4_echo_reply
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv4(ipv4_source, ipv4_dest, ipv4_time_to_live)
                .icmpv6_echo_reply(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv6Type::EchoReply(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }
    }
}

proptest! {
    #[test]
    fn ipv6_icmpv4(
        ipv6_source in any::<[u8;16]>(),
        ipv6_dest in any::<[u8;16]>(),
        ipv6_hop_limit in any::<u8>(),
        icmpv4_type_u8 in 15u8..u8::MAX,
        icmpv4_code_u8 in any::<u8>(),
        icmpv4_bytes5to8 in any::<[u8;4]>(),
        icmpv4 in icmpv4_type_any(),
        echo_id in any::<u16>(),
        echo_seq in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test_builder = |builder: PacketBuilderStep<Icmpv4Header>, icmpv4_type: Icmpv4Type| {

            use Icmpv4Type::*;
            let adapted_payload = match icmpv4_type {
                TimestampRequest(_) | TimestampReply(_) => &[],
                _ => &payload[..],
            };

            let icmp_expected = Icmpv4Header::with_checksum(icmpv4_type, &adapted_payload);
            let ip_expected = Ipv6Header{
                traffic_class: 0,
                flow_label: 0,
                payload_length: (icmp_expected.header_len() + adapted_payload.len()) as u16,
                next_header: ip_number::ICMP,
                hop_limit: ipv6_hop_limit,
                source: ipv6_source,
                destination: ipv6_dest
            };

            // test builder.size()
            assert_eq!(
                builder.size(adapted_payload.len()),
                Ethernet2Header::SERIALIZED_SIZE +
                Ipv6Header::SERIALIZED_SIZE +
                icmp_expected.header_len() +
                adapted_payload.len()
            );

            // test builder.write()
            let mut buffer = Vec::<u8>::with_capacity(builder.size(adapted_payload.len()));
            builder.write(&mut buffer, adapted_payload).unwrap();

            // decode packets
            let actual = PacketHeaders::from_ethernet_slice(&buffer).unwrap();

            // check the packets could be decoded
            assert_eq!(
                Some(Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: ether_type::IPV6
                }),
                actual.link
            );
            assert_eq!(
                Some(IpHeader::Version6(ip_expected, Default::default())),
                actual.ip
            );
            assert_eq!(
                Some(TransportHeader::Icmpv4(icmp_expected)),
                actual.transport
            );
            assert_eq!(actual.payload, adapted_payload);
        };

        // icmpv4
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv4(icmpv4.clone());

            test_builder(
                builder,
                icmpv4
            );
        }

        // icmpv4_raw
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv4_raw(icmpv4_type_u8, icmpv4_code_u8, icmpv4_bytes5to8);

            test_builder(
                builder,
                Icmpv4Type::Unknown{
                    type_u8: icmpv4_type_u8,
                    code_u8: icmpv4_code_u8,
                    bytes5to8: icmpv4_bytes5to8,
                }
            );
        }

        // icmpv4_echo_request
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv4_echo_request(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv4Type::EchoRequest(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }

        // icmp4_echo_reply
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv4_echo_reply(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv4Type::EchoReply(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }
    }
}

proptest! {
    #[test]
    fn ipv6_icmpv6(
        ipv6_source in any::<[u8;16]>(),
        ipv6_dest in any::<[u8;16]>(),
        ipv6_hop_limit in any::<u8>(),
        icmpv6_type_u8 in 162u8..u8::MAX,
        icmpv6_code_u8 in any::<u8>(),
        icmpv6_bytes5to8 in any::<[u8;4]>(),
        icmpv6 in icmpv6_type_any(),
        echo_id in any::<u16>(),
        echo_seq in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test_builder = |builder: PacketBuilderStep<Icmpv6Header>, icmpv6_type: Icmpv6Type| {
            let icmp_expected = Icmpv6Header::with_checksum(
                icmpv6_type,
                ipv6_source,
                ipv6_dest,
                &payload
            ).unwrap();
            let ip_expected = Ipv6Header{
                traffic_class: 0,
                flow_label: 0,
                payload_length: (icmp_expected.header_len() + payload.len()) as u16,
                next_header: ip_number::IPV6_ICMP,
                hop_limit: ipv6_hop_limit,
                source: ipv6_source,
                destination: ipv6_dest
            };

            // test builder.size()
            assert_eq!(
                builder.size(payload.len()),
                Ethernet2Header::SERIALIZED_SIZE +
                Ipv6Header::SERIALIZED_SIZE +
                icmp_expected.header_len() +
                payload.len()
            );

            // test builder.write()
            let mut buffer = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut buffer, &payload).unwrap();

            // decode packets
            let actual = PacketHeaders::from_ethernet_slice(&buffer).unwrap();

            // check the packets could be decoded
            assert_eq!(
                Some(Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: ether_type::IPV6
                }),
                actual.link
            );
            assert_eq!(
                Some(IpHeader::Version6(ip_expected, Default::default())),
                actual.ip
            );
            assert_eq!(
                Some(TransportHeader::Icmpv6(icmp_expected)),
                actual.transport
            );
            assert_eq!(actual.payload, &payload);
        };

        // icmpv6
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv6(icmpv6.clone());

            test_builder(
                builder,
                icmpv6
            );
        }

        // icmpv6_raw
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv6_raw(icmpv6_type_u8, icmpv6_code_u8, icmpv6_bytes5to8);

            test_builder(
                builder,
                Icmpv6Type::Unknown{
                    type_u8: icmpv6_type_u8,
                    code_u8: icmpv6_code_u8,
                    bytes5to8: icmpv6_bytes5to8,
                }
            );
        }

        // icmpv6_echo_request
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv6_echo_request(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv6Type::EchoRequest(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }

        // icmp4_echo_reply
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                .ipv6(ipv6_source, ipv6_dest, ipv6_hop_limit)
                .icmpv6_echo_reply(echo_id, echo_seq);

            test_builder(
                builder,
                Icmpv6Type::EchoReply(IcmpEchoHeader{
                    id: echo_id,
                    seq: echo_seq,
                })
            );
        }
    }
}
