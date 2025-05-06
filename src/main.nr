fn main(msg_hash: [u8; 32], signature: [u8; 64], pubkey_x: [u8; 32], pubkey_y: [u8; 32]) {
    let sig_valid: bool =
        std::ecdsa_secp256k1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash);
    // sig_valid
    assert(sig_valid == true)
}
