const crypto = require("crypto");
const secp256k1 = require("secp256k1"); 

let privKey;
do {
  privKey = crypto.randomBytes(32);
} while (!secp256k1.privateKeyVerify(privKey));

// 2. Get the public key in uncompressed format (65 bytes: 0x04 + X(32) + Y(32))
const pubKey = secp256k1.publicKeyCreate(privKey, false);
const pubKeyX = pubKey.slice(1, 33); 
const pubKeyY = pubKey.slice(33, 65); 

const message = "GeneralElectric|Ferguson|166000|SRN9375802855|";
console.log("message: [");
for (const b of Buffer.from(message, "utf8")) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");
const msgHash = crypto.createHash("sha256").update(message).digest(); 

const { signature } = secp256k1.ecdsaSign(msgHash, privKey);

//  Normalize signature to (r + s) 64 bytes
// const sigCompact = secp256k1.signatureExport(signature); 
const sigCompact = signature;
console.log("\n--- Noir Test Data ---\n");

console.log("msg_hash: [");
for (const b of msgHash) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

console.log("signature: [");
for (const b of sigCompact) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

console.log("pubkey_x: [");
for (const b of pubKeyX) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]\n");

console.log("pubkey_y: [");
for (const b of pubKeyY) {
  process.stdout.write(`0x${b.toString(16).padStart(2, "0")}, `);
}
console.log("]");
