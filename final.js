const crypto = require("crypto");
const secp256k1 = require("secp256k1"); // install via: npm install secp256k1

// 1. Generate a private key
let privKey;
do {
  privKey = crypto.randomBytes(32);
} while (!secp256k1.privateKeyVerify(privKey));

// 2. Get the public key in uncompressed format (65 bytes: 0x04 + X(32) + Y(32))
const pubKey = secp256k1.publicKeyCreate(privKey, false);
const pubKeyX = pubKey.slice(1, 33); // 32 bytes
const pubKeyY = pubKey.slice(33, 65); // 32 bytes

// 3. Message and hash
const message = "Hello Noir + ECDSA!";
const msgHash = crypto.createHash("sha256").update(message).digest(); // 32 bytes

// 4. Sign the message hash
const { signature } = secp256k1.ecdsaSign(msgHash, privKey);

// 5. Normalize signature to (r + s) 64 bytes
// const sigCompact = secp256k1.signatureExport(signature); // already 64 bytes
const sigCompact = signature;
console.log("\n--- Noir Test Data ---\n");

// Print message hash
console.log("msg_hash: [");
for (const b of msgHash) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

// Print signature
console.log("signature: [");
for (const b of sigCompact) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

// Print pubkey_x
console.log("pubkey_x: [");
for (const b of pubKeyX) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

// Print pubkey_y
console.log("pubkey_y: [");
for (const b of pubKeyY) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]");
