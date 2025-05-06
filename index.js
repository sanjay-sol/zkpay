const { time, timeStamp } = require("console");
const crypto = require("crypto");

// 1. Generate ECDSA key pair on secp256r1 (prime256v1)
const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "prime256v1", // “prime256v1” is the OpenSSL name for secp256r1:contentReference[oaicite:1]{index=1}
});
// 2. Construct the message and hash it with SHA-256
const message = "Alice|Bob|100|2025-05-06T14:00:00Z|PAY123XYZ";
const msgBuf = Buffer.from(message, 'utf8');
// Sign with SHA-256. Node will hash msgBuf internally with SHA-256.
const signature = crypto.sign(
  'sha256', 
  msgBuf, 
  { key: privateKey, dsaEncoding: 'ieee-p1363' }
); // signature is a 64-byte Buffer = R||S:contentReference[oaicite:3]{index=3}
// const hash = crypto.createHash("sha256").update(message, "utf8").digest();
const msgHash = crypto.createHash('sha256').update(message).digest(); // 32-byte Buffer
console.log(Array.from(msgHash));

const der = publicKey.export({ type: 'spki', format: 'der' });
// Skip algorithm headers; the public key BIT STRING typically has a 0x04 prefix for uncompressed form.
const pubKeyBytes = der.slice(-65);      // last 65 bytes: 0x04 || X || Y
const rawX = pubKeyBytes.slice(1,33);    // bytes 1–32 = X
const rawY = pubKeyBytes.slice(33,65);   // bytes 33–64 = Y

// 3. Sign the hash (ECDSA). Use dsaEncoding:'ieee-p1363' to get a raw (r||s) 64-byte signature:contentReference[oaicite:2]{index=2}.
// const signature = crypto.sign(null, hash, {
//   key: privateKey,
//   dsaEncoding: "ieee-p1363",
// });
// 4. Extract r and s from the signature buffer
// const r = signature.slice(0, 32);
// const s = signature.slice(32, 64);

// 5. Extract public key coordinates (x, y) from the SubjectPublicKeyInfo DER
// const pubDer = publicKey.export({ type: "spki", format: "der" });
// const bitStringIndex = pubDer.indexOf(0x03); // find BIT STRING tag (0x03)
// const bitStringLength = pubDer[bitStringIndex + 1]; // length byte (should be 66 for secp256r1)
// const bitStringStart = bitStringIndex + 2; // skip tag and length
// const unusedBits = pubDer[bitStringStart]; // usually 0
// const pubBytes = pubDer.slice(bitStringStart + 1);
// console.log(pubBytes[0]);
// skip the 'unused bits' byte
// pubBytes now starts with 0x04 followed by X||Y
// if (pubBytes[0] !== 0x04) {
//   throw new Error("Unexpected public key format");
// }
// const x = pubBytes.slice(1, 33); // first 32 bytes of (X)
// const y = pubBytes.slice(33, 65); // next 32 bytes (Y)
// 6. Prepare output arrays (Uint8 values)
const signatureArray = Array.from(signature); // 64-byte [r||s]
// const pubXArray = Array.from(x); // 32-byte X
// const pubYArray = Array.from(y); // 32-byte Y
const senderArray = Array.from(Buffer.from("Alice", "utf8"));
const receiverArray = Array.from(Buffer.from("Bob", "utf8"));
const amountArray = Array.from(Buffer.from("100", "utf8"));
const timestampArray = Array.from(Buffer.from("2025-05-06T14:00:00Z", "utf8"));
const paymentIdArray = Array.from(Buffer.from("PAY123XYZ", "utf8"));

console.log("sig----------");
console.log(signatureArray);
console.log("X----------");
console.log(Array.from(rawX));
console.log("Y----------");
console.log(Array.from(rawY));
console.log("Send----------");
console.log(senderArray);
console.log("Rec----------");
console.log(receiverArray);
console.log("Amoi----------");
console.log(amountArray);
console.log("time----------");
console.log(timestampArray);
console.log("pay----------");
console.log(paymentIdArray);
console.log("XXXX----------");
