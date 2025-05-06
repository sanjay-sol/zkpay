const crypto = require("crypto");

// Generate ECDSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "secp256k1", // commonly used curve (same as Bitcoin, Ethereum)
});

// Message to be signed
const message = "Hello, ECDSA!";

// Hash the message
const hash = crypto.createHash("sha256").update(message).digest();

// Sign the message hash
const signature = crypto.sign(null, hash, privateKey);

// Verify the signature
const isVerified = crypto.verify(null, hash, publicKey, signature);

console.log("Signature (hex):", signature.toString("hex"));
console.log("Hashed Message (hex):", hash.toString("hex"));
console.log(
  "Public Key (PEM):\n",
  publicKey.export({ type: "spki", format: "pem" })
);
console.log("Signature Valid:", isVerified);
