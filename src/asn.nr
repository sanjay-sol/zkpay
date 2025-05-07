global MAX_BUFFER_SIZE: u32 = 8192;
global OCTET_LEN: u32 = 1024;

struct Stream {
    enc: [u8; MAX_BUFFER_SIZE],
    pos: u32,
}

impl Stream {
    pub fn new(input_data: [u8; MAX_BUFFER_SIZE]) -> Stream {
        Stream { enc: input_data, pos: 0 }
    }

    pub fn get(self, pos: u32) -> u8 {
        assert(pos < MAX_BUFFER_SIZE, "Position out of bounds");
        self.enc[pos]
    }

    pub fn get_next(mut self) -> (u8, Stream) {
        assert(self.pos < MAX_BUFFER_SIZE, "Position out of bounds");
        let byte = self.enc[self.pos];
        self.pos += 1;
        (byte, self)
    }

    pub fn get_bytes(self, offset: u32, length: u32) -> ([u8; MAX_BUFFER_SIZE], u32) {
        assert(offset + length <= MAX_BUFFER_SIZE, "Slice out of bounds");
        let mut result: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
        for i in 0..length {
            result[i] = self.enc[offset + i];
        }
        (result, length)
    }

    pub fn parse_octet_string(self, start: u32, end: u32) -> ([u8; OCTET_LEN], u32) {
        let len = end - start;
        assert(len <= OCTET_LEN, "Octet string length exceeds maximum");

        let mut result: [u8; OCTET_LEN] = [0; OCTET_LEN];
        for i in 0..len {
            result[i] = self.enc[start + i];
        }
        (result, len)
    }
}

#[test]
fn test_stream_get_and_bytes() {
    let mut data: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
    data[0] = 0xDE;
    data[1] = 0xAD;
    data[2] = 0xBE;
    data[3] = 0xEF;
    let stream = Stream::new(data);

    assert_eq(stream.get(0), 0xDE);
    assert_eq(stream.get(1), 0xAD);
    assert_eq(stream.get(2), 0xBE);
    assert_eq(stream.get(3), 0xEF);

    let mut data2: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
    for i in 0..10 {
        data2[i] = i as u8;
    }
    let stream2 = Stream::new(data2);

    let (bytes, size) = stream2.get_bytes(0, 4);
    assert_eq(size, 4);
    for i in 0..4 {
        assert_eq(bytes[i], i as u8);
    }

    let (bytes2, size2) = stream2.get_bytes(4, 3);
    assert_eq(size2, 3);
    for i in 0..3 {
        assert_eq(bytes2[i], (4 + i) as u8);
    }
}

#[test]
fn test_parse_octet_string() {
    let mut data: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
    data[0] = 0xAB;
    data[1] = 0xCD;
    data[2] = 0xEF;
    data[3] = 0x12;
    data[4] = 0x34;
    data[5] = 0x56;
    let stream = Stream::new(data);

    let (bytes, size) = stream.parse_octet_string(0, 6);
    assert_eq(size, 6);
    let expected: [u8; 6] = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56];
    for i in 0..6 {
        assert_eq(bytes[i], expected[i]);
    }
}
