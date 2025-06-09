fn parse_tag(data: [u8; 4096], offset: u64) -> (u8, u64) {
    let first = data[offset];
    if (first & 0x1F) != 0x1F {
        return (first, 1u64);
    } else {
        let mut idx = offset + 1u64;
        while data[idx] & 0x80 != 0 {
            idx += 1u64;
        }
        idx += 1u64;
        let tag_len = idx - offset;
        return (first, tag_len);
    }
}

fn parse_length(data: [u8; 4096], offset: u64) -> (u64, u64) {
    let first = data[offset];
    if first & 0x80 == 0 {
        return ((first & 0x7F) as u64, 1u64);
    } else {

        let num_bytes = (first & 0x7F) as u64;

        assert(first != 0x80, "Indefinite length not allowed in DER");
        assert(num_bytes > 0u64, "Invalid DER length encoding");
        let mut val: u64 = 0;
        for i in 1u64..=num_bytes {
            val = (val << 8) + (data[offset + i] as u64);
        }
        return (val, 1u64 + num_bytes);
    }
}

fn parse_tlv(data: [u8; 4096], offset: u64) -> (u8, u64, u64) {
    let (tag, tag_len) = parse_tag(data, offset);
    let (len, len_len) = parse_length(data, offset + tag_len);
    return (tag, len, tag_len + len_len);
}
