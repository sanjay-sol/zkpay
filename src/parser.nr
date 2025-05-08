mod util;

pub fn parse_certificate(data: [u8; 4096]) -> (
    [u8; 1024], // modulus as hex
    [u8;    8], // exponent as hex (supports up to 4 bytes, hex padded to 8 chars)
    [u8;  128], // message digest as hex (up to 64 bytes digest)
    [u8; 1024]  // signature as hex
) {

    let (cert_tag, cert_len, cert_hdr) = parse_tlv(data, 0);
    assert!(cert_tag == 0x30, "Expected SEQUENCE at certificate start");

    let tbs_offset = cert_hdr;
    let (tbs_tag, tbs_len, tbs_hdr) = parse_tlv(data, tbs_offset);
    assert!(tbs_tag == 0x30, "Expected SEQUENCE for tbsCertificate");
    let tbs_start = tbs_offset + tbs_hdr;
    let tbs_end = tbs_offset + tbs_hdr + tbs_len;
    let mut offset = tbs_start;
    if data[offset] == 0xA0 {
        let (_, ver_len, ver_hdr) = parse_tlv(data, offset);
        offset += ver_hdr + ver_len;  
    }
    {
        let (tag, len, hdr) = parse_tlv(data, offset);
        assert!(tag == 0x02, "Expected INTEGER for serialNumber");
        offset += hdr + len;
    }
    {
        let (tag, len, hdr) = parse_tlv(data, offset);

        offset += hdr + len;
    }

    {
        let (tag, len, hdr) = parse_tlv(data, offset);
        assert!(tag == 0x30, "Expected SEQUENCE for issuer");
        offset += hdr + len;
    }

    {
        let (tag, len, hdr) = parse_tlv(data, offset);
        assert!(tag == 0x30, "Expected SEQUENCE for validity");
        offset += hdr + len;
    }

    {
        let (tag, len, hdr) = parse_tlv(data, offset);
        assert!(tag == 0x30, "Expected SEQUENCE for subject");
        offset += hdr + len;
    }

    let (spki_tag, spki_len, spki_hdr) = parse_tlv(data, offset);
    assert!(spki_tag == 0x30, "Expected SEQUENCE for SubjectPublicKeyInfo");
    let spki_start = offset + spki_hdr;
    let spki_end = offset + spki_hdr + spki_len;
    offset = spki_start;

    {
        let (_, alg_len, alg_hdr) = parse_tlv(data, offset);
        offset += alg_hdr + alg_len;
    }

    let (bs_tag, bs_len, bs_hdr) = parse_tlv(data, offset);
    assert!(bs_tag == 0x03, "Expected BIT STRING for publicKey");
    let bitstr_start = offset + bs_hdr;

    let pad_bits = data[bitstr_start];
    assert!(pad_bits == 0, "Non-zero pad bits in BIT STRING");
    let rsa_seq_offset = bitstr_start + 1;

    let (rsa_tag, rsa_len, rsa_hdr) = parse_tlv(data, rsa_seq_offset);
    assert!(rsa_tag == 0x30, "Expected SEQUENCE for RSAPublicKey");
    let rsa_start = rsa_seq_offset + rsa_hdr;
    offset = rsa_start;

    let (mod_tag, mod_len, mod_hdr) = parse_tlv(data, offset);
    assert!(mod_tag == 0x02, "Expected INTEGER for modulus");
    let mod_content = offset + mod_hdr;
    let mod_len_u = mod_len;
    offset += mod_hdr + mod_len;

    let (exp_tag, exp_len, exp_hdr) = parse_tlv(data, offset);
    assert!(exp_tag == 0x02, "Expected INTEGER for exponent");
    let exp_content = offset + exp_hdr;
    let exp_len_u = exp_len;

    let mut digest_bytes: [u8; 64] = [0u8; 64];
    if offset < tbs_end & data[offset] == 0xA3 {

        let (_, ext_sect_len, ext_sect_hdr) = parse_tlv(data, offset);

        let ext_seq_offset = offset + ext_sect_hdr;
        let (exts_tag, exts_len, exts_hdr) = parse_tlv(data, ext_seq_offset);
        assert!(exts_tag == 0x30, "Expected SEQUENCE for extensions");
        let mut ext_offset = ext_seq_offset + exts_hdr;
        let ext_end = ext_seq_offset + exts_hdr + exts_len;

        while ext_offset < ext_end {
            let (ext_tag, ext_len, ext_hdr2) = parse_tlv(data, ext_offset);

            ext_offset += ext_hdr2;
            let (oid_tag, oid_len, oid_hdr) = parse_tlv(data, ext_offset);
            assert!(oid_tag == 0x06, "Expected OID in extension");
            let oid_start = ext_offset + oid_hdr;

            let mut oid_buf: [u8; 9] = [0u8; 9];
            for i in 0..9 {
                oid_buf[i] = data[oid_start + i];
            }
            ext_offset += oid_hdr + oid_len;

            let md_oid: [u8;9] = [42, 134, 72, 134, 247, 13, 1, 9, 4];
            if oid_buf == md_oid {
                if data[ext_offset] == 0x01 {
                    let (_, _, bool_hdr) = parse_tlv(data, ext_offset);
                    ext_offset += bool_hdr + 1; 
                }
                let (val_tag, val_len, val_hdr) = parse_tlv(data, ext_offset);
                assert!(val_tag == 0x04, "Expected OCTET STRING for messageDigest");
                let val_start = ext_offset + val_hdr;
                let to_copy = if val_len > 64u64 { 64u64 } else { val_len } as u64;
                for i in 0..to_copy {
                    digest_bytes[i as usize] = data[val_start + i];
                }
                break;
            }

            let (_, val_len2, val_hdr2) = parse_tlv(data, ext_offset);
            ext_offset += val_hdr2 + val_len2;
        }
    }

    let sig_alg_offset = tbs_offset + tbs_hdr + tbs_len;
    let (_, sig_alg_len, sig_alg_hdr) = parse_tlv(data, sig_alg_offset);
    let sig_val_offset = sig_alg_offset + sig_alg_hdr + sig_alg_len;
    let (sig_tag, sig_len, sig_hdr2) = parse_tlv(data, sig_val_offset);
    assert!(sig_tag == 0x03, "Expected BIT STRING for signatureValue");
    let sig_start = sig_val_offset + sig_hdr2 + 1;
    let sig_bytes_len = sig_len - 1; 

    let mut mod_hex: [u8; 1024] = [b'0'; 1024];
    let mut exp_hex: [u8; 8]    = [b'0';   8];
    let mut digest_hex: [u8; 128] = [b'0'; 128];
    let mut sig_hex: [u8; 1024] = [b'0'; 1024];
    let mod_bytes_len = mod_len_u as usize;
    let mod_offset = 1024 - (mod_bytes_len * 2);
    for i in 0..mod_bytes_len {
        let byte = data[mod_content + (i as u64)];
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        mod_hex[mod_offset + 2*i    ] = if hi < 10 { (b'0' + hi as u8) } else { (b'A' + (hi-10) as u8) };
        mod_hex[mod_offset + 2*i + 1] = if lo < 10 { (b'0' + lo as u8) } else { (b'A' + (lo-10) as u8) };
    }

    assert!(exp_len_u <= 4u64, "Exponent too large");
    let exp_bytes_len = exp_len_u as usize;
    let exp_offset = 8 - (exp_bytes_len * 2);
    for i in 0..exp_bytes_len {
        let byte = data[exp_content + (i as u64)];
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        exp_hex[exp_offset + 2*i    ] = if hi < 10 { (b'0' + hi as u8) } else { (b'A' + (hi-10) as u8) };
        exp_hex[exp_offset + 2*i + 1] = if lo < 10 { (b'0' + lo as u8) } else { (b'A' + (lo-10) as u8) };
    }
    for i in 0..64 {
        let byte = digest_bytes[i];
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        digest_hex[2*i    ] = if hi < 10 { (b'0' + hi as u8) } else { (b'A' + (hi-10) as u8) };
        digest_hex[2*i + 1] = if lo < 10 { (b'0' + lo as u8) } else { (b'A' + (lo-10) as u8) };
    }
    let sig_len_u = sig_bytes_len;
    let sig_bytes_len = sig_len_u as usize;
    let sig_offset = 1024 - (sig_bytes_len * 2);
    for i in 0..sig_bytes_len {
        let byte = data[sig_start + (i as u64)];
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        sig_hex[sig_offset + 2*i    ] = if hi < 10 { (b'0' + hi as u8) } else { (b'A' + (hi-10) as u8) };
        sig_hex[sig_offset + 2*i + 1] = if lo < 10 { (b'0' + lo as u8) } else { (b'A' + (lo-10) as u8) };
    }

    return (mod_hex, exp_hex, digest_hex, sig_hex);
}
