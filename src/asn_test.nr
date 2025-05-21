struct ParsedCert {
    version: u32,
    serial: u64,
    issuer_cn: [u8; 32],
    subject_cn: [u8; 32],
    not_before: [u8; 13],
    not_after: [u8; 13],
    pub_key: [u8; 32],
    signature: [u8; 64],
}

fn parse_certificate(cert: [u8; 509]) -> ParsedCert {
    assert(cert[0] == 0x30);
    assert(cert[1] == 0x82);
    let total_len = (cert[2] as u32) << 8 | (cert[3] as u32);
    assert(total_len == 505); // 509 - 4

    let mut version: u32 = 0;
    let mut offset: u32 = 0 ;

    if cert[4] == 0xA0 {
        assert(cert[6] == 0x02);
        assert(cert[7] == 0x01);
        version = cert[8] as u32;
        offset = 9;
    } else {
        version = 1;
        offset = 4;
    }

    // SERIAL (INTEGER)
    assert(cert[offset] == 0x02);
    let serial_len = cert[(offset + 1)] as u32;
    let mut serial: u64 = 0;
    for i in 0..serial_len {
        serial = (serial << 8) | (cert[(offset + 2 + i)] as u64);
    }
    offset += 2 + serial_len;

    // Skip SignatureAlgorithm SEQUENCE
    assert(cert[offset ] == 0x30);
    let sigalg_len = cert[(offset + 1) ] as u32 + 2;
    offset += sigalg_len;

    // ISSUER Name
    assert(cert[offset ] == 0x30);
    let issuer_len = cert[(offset + 1) ] as u32;
    let cn_offset = offset + 6;
    let cn_len = cert[(cn_offset + 1) ] as u32;
    let mut issuer_cn: [u8; 32] = [0; 32];
    for i in 0..cn_len {
        issuer_cn[i ] = cert[(cn_offset + 2 + i) ];
    }
    offset += 2 + issuer_len;

    // VALIDITY
    assert(cert[offset ] == 0x30);
    let valid_len = cert[(offset + 1) ] as u32;
    assert(cert[(offset + 2) ] == 0x17);
    let mut not_before: [u8; 13] = [0; 13];
    for i in 0..13 {
        not_before[i ] = cert[(offset + 3 + i) ];
    }
    let mut not_after: [u8; 13] = [0; 13];
    for i in 0..13 {
        not_after[i ] = cert[(offset + 3 + 13 + i) ];
    }
    offset += 2 + valid_len;

    // SUBJECT Name
    assert(cert[offset ] == 0x30);
    let subject_len = cert[(offset + 1) ] as u32;
    let cn_offset2 = offset + 6;
    let cn_len2 = cert[(cn_offset2 + 1) ] as u32;
    let mut subject_cn: [u8; 32] = [0; 32];
    for i in 0..cn_len2 {
        subject_cn[i ] = cert[(cn_offset2 + 2 + i) ];
    }
    offset += 2 + subject_len;

    // SubjectPublicKeyInfo
    assert(cert[offset ] == 0x30);
    offset += 6; // skip inner algorithm SEQ
    assert(cert[offset ] == 0x03);
    let _bs_len = cert[(offset + 1) ];
    offset += 2; // move to bitstring
    offset += 1; // skip unused bits indicator
    let mut pub_key: [u8; 32] = [0; 32];
    for i in 0..32 {
        pub_key[i ] = cert[(offset + i) ];
    }
    offset += 32;

    // Search for SignatureValue BIT STRING (tag 0x03)
let mut sig_offset: u32 = offset;
let mut found: u32 = 0;

for i in 0..20 {
    let is_match = if cert[(offset + i)] == 0x03 { 1 } else { 0 }; // returns u32 now
    found += is_match;
    sig_offset = if (is_match == 1) & (found == 1) {
        offset + i
    } else {
        sig_offset
    };
}

assert(found == 1);


// Ensure we found it exactly once
assert(found == 1);
    let _sig_len = cert[(sig_offset + 1) ];
    sig_offset += 2;
    let mut signature: [u8; 64] = [0; 64];
    for i in 0..64 {
        signature[i ] = cert[(sig_offset + i) ];
    }

    ParsedCert {
        version,
        serial,
        issuer_cn,
        subject_cn,
        not_before,
        not_after,
        pub_key,
        signature,
    }
}


#[test]
fn test_parse_certificate_valid() {
    let mut cert: [u8; 509] = [0; 509];

    // Certificate header
    cert[0] = 0x30;
    cert[1] = 0x82;
    cert[2] = 0x01; // 505 in big-endian
    cert[3] = 0xF9;

    // Version info (explicit v2 format)
    cert[4] = 0xA0;
    cert[5] = 0x03;
    cert[6] = 0x02;
    cert[7] = 0x01;
    cert[8] = 2;

    let mut offset: u32 = 9;

    // Serial
    cert[offset] = 0x02;
    cert[offset + 1] = 0x02;
    cert[offset + 2] = 0x12;
    cert[offset + 3] = 0x34;
    offset += 4;

    // Signature Algorithm Sequence
    cert[offset] = 0x30;
    cert[offset + 1] = 0x05;
    offset += 7;

    // Issuer
    cert[offset] = 0x30;
    cert[offset + 1] = 0x09;
    cert[offset + 6] = 0x0C; // PrintableString tag
    cert[offset + 7] = 0x03;
    cert[offset + 8] = 0x41; // 'A'
    cert[offset + 9] = 0x42; // 'B'
    cert[offset + 10] = 0x43; // 'C'
    offset += 11;

    // Validity
    cert[offset] = 0x30;
    cert[offset + 1] = 0x1A;
    cert[offset + 2] = 0x17; // notBefore tag
    for i in 0..13 {
        cert[offset + 3 + i] = i as u8;
    }
    for i in 0..13 {
        cert[offset + 3 + 13 + i] = (i + 20) as u8;
    }
    offset += 2 + 26;

    // Subject
    cert[offset] = 0x30;
    cert[offset + 1] = 0x09;
    cert[offset + 6] = 0x0C; // PrintableString tag
    cert[offset + 7] = 0x03;
    cert[offset + 8] = 0x44; // 'D'
    cert[offset + 9] = 0x45; // 'E'
    cert[offset + 10] = 0x46; // 'F'
    offset += 11;

    // Public Key Info
    cert[offset] = 0x30;
    offset += 6;
    cert[offset] = 0x03;
    cert[offset + 1] = 0x21;
    cert[offset + 2] = 0x00; // unused bits indicator
    for i in 0..32 {
        cert[offset + 3 + i] = (100 + i) as u8;
    }
    offset += 3 + 32;

    // Search for signature BIT STRING (tag 0x03)
    cert[offset + 5] = 0x03;
    cert[offset + 6] = 0x40;
    for i in 0..64 {
        cert[offset + 7 + i] = (200 + i) as u8;
    }

    let parsed = parse_certificate(cert);

    assert(parsed.version == 2);
    assert(parsed.serial == 0x1234);
    assert(parsed.issuer_cn[0] == 0x41); // 'A'
    assert(parsed.issuer_cn[1] == 0x42); // 'B'
    assert(parsed.issuer_cn[2] == 0x43); // 'C'
    assert(parsed.subject_cn[0] == 0x44); // 'D'
    assert(parsed.subject_cn[1] == 0x45); // 'E'
    assert(parsed.subject_cn[2] == 0x46); // 'F'
    assert(parsed.pub_key[0] == 100);
    assert(parsed.signature[0] == 200);
    // assert(parsed.signature[63] == 263);
}
