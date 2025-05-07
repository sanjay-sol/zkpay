fn parse_tag(data: [u8; 4096], offset: u64) -> (u8, u64) {
    let first = data[offset];
    if (first & 0x1F) != 0x1F {
        (first, 1 as u64)
    } else {
        let mut idx = offset + 1 as u64;

        for _ in 0..10 {
            let byte = data[idx];
            idx += 1 as u64;
            if byte & 0x80 == 0 {}
        }

        let tag_len = idx - offset;
        (first, tag_len)
    }
}

fn parse_length(data: [u8; 4096], offset: u64) -> (u64, u64) {
    let first = data[offset];
    if first & 0x80 == 0 {
        // Short form: length = first & 0x7F (fits 0-127):contentReference[oaicite:8]{index=8}
        ((first & 0x7F) as u64, 1 as u64)
    } else {
        // Long form: lower 7 bits = number of subsequent length bytes
        let num_bytes = (first & 0x7F) as u64;
        // DER forbids indefinite length (0x80) and requires minimal encoding
        assert(first != 0x80, "Indefinite length not allowed in DER");
        assert(num_bytes > 0 as u64, "Invalid DER length encoding");
        // Parse big-endian length
        let mut val: u64 = 0;
        for i in 1..=num_bytes {
            val = (val << 8) + (data[offset + i] as u64);
        }
        (val, 1 as u64 + num_bytes)
    }
}

/// Parse a TLV at `offset`: returns (tagByte, valueLength, totalHeaderLength).
fn parse_tlv(data: [u8; 4096], offset: u64) -> (u8, u64, u64) {
    let (tag, tag_len) = parse_tag(data, offset);
    let (len, len_len) = parse_length(data, offset + tag_len);
    (tag, len, tag_len + len_len)
}
