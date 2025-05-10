fn hex_char_to_nibble(c: u8) -> u8 {
    let is_digit: u8 = if (c >= 48) & (c <= 57) { 1 } else { 0 };
    let is_upper: u8 = if (c >= 65) & (c <= 70) { 1 } else { 0 };
    let is_lower: u8 = if (c >= 97) & (c <= 102) { 1 } else { 0 };

    let digit_val = (c - 48) * is_digit;
    let upper_val = (c - 65 + 10) * is_upper;
    let lower_val = (c - 97 + 10) * is_lower;

    let is_valid = is_digit + is_upper + is_lower;
    assert(is_valid == 1, "Invalid hex character");

    let val = digit_val + upper_val + lower_val;
    val
}


fn hex_decode(hex: [u8; 4]) -> [u8; 2] {
    let mut out: [u8; 2] = [0; 2];

    for i in 0..2 {
        let high = hex_char_to_nibble(hex[2 * i]);
        let low = hex_char_to_nibble(hex[2 * i + 1]);
        out[i] = high * 16 + low;
    }

    out
}

#[test]
fn test_uppercase() {
    let hex: [u8; 4] = [52, 49, 52, 50]; // "4142"
    let out = hex_decode(hex);
    println("Uppercase test:");
    println(out[0]);
    println(out[1]);
    assert(out[0] == 65); // 'A'
    assert(out[1] == 66); // 'B'
}

#[test]
fn test_lowercase() {
    let hex: [u8; 4] = [54, 49, 54, 50]; // "6162"
    let out = hex_decode(hex);
    println("Lowercase test:");
    println(out[0]);
    println(out[1]);
    assert(out[0] == 97); // 'a'
    assert(out[1] == 98); // 'b'
}

#[test]
fn test_mixed_case() {
    let hex: [u8; 4] = [52, 49, 54, 50]; // "4162"
    let out = hex_decode(hex);
    println("Mixed case test:");
    println(out[0]);
    println(out[1]);
    assert(out[0] == 65); // 'A'
    assert(out[1] == 98); // 'b'
}

#[test(should_fail)]
fn test_invalid_character() {
    let hex: [u8; 4] = [52, 71, 52, 50]; // "4G42", 71='G'
    let _out = hex_decode(hex);
}

#[test(should_fail)]
fn test_incomplete_length() {
    // Noir requires fixed array sizes, so we simulate a bad char.
    let hex: [u8; 4] = [52, 49, 52, 255]; // 255 is invalid
    let _out = hex_decode(hex);
}
