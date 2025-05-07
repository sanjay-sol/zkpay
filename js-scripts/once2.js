const crypto = require("crypto");
const fs = require("fs");

// Load the private key (same key every time!)
const privateKey = crypto.createPrivateKey(fs.readFileSync("private.pem"));
const publicKey = crypto.createPublicKey(privateKey);

// Construct the message
const message = "Alice|Bob|100|2025-05-06T14:00:00Z|PAY123XYZ";
const msgBuf = Buffer.from(message, "utf8");

// 🔒 Sign (SHA-256 + secp256r1)
const signature = crypto.sign(
  "sha256",
  msgBuf,
  { key: privateKey, dsaEncoding: "ieee-p1363" } // 64 bytes: r || s
);

// Hash the message (for info)
const msgHash = crypto.createHash("sha256").update(message).digest();

// Extract X/Y public key from PEM (so Noir can hardcode it)
const der = publicKey.export({ type: "spki", format: "der" });
const pubKeyBytes = der.slice(-65); // last 65 bytes: 0x04 || X || Y
const rawX = pubKeyBytes.slice(1, 33); // 32 bytes
const rawY = pubKeyBytes.slice(33, 65); // 32 bytes

// Prepare test arrays
const signatureArray = Array.from(signature);
const msgHashArray = Array.from(msgHash);
const senderArray = Array.from(Buffer.from("Alice", "utf8"));
const receiverArray = Array.from(Buffer.from("Bob", "utf8"));
const timestampArray = Array.from(Buffer.from("2025-05-06T14:00:00Z", "utf8"));
const paymentIdArray = Array.from(Buffer.from("PAY123XYZ", "utf8"));
const pubXArray = Array.from(rawX);
const pubYArray = Array.from(rawY);

console.log("Signature:", signatureArray);
console.log("Message Hash:", msgHashArray);
console.log("Public Key X:", pubXArray);
console.log("Public Key Y:", pubYArray);
console.log("Sender:", senderArray);
console.log("Receiver:", receiverArray);
console.log("Timestamp:", timestampArray);
console.log("Payment ID:", paymentIdArray);
