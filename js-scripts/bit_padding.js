const crypto = require("crypto");
const secp256k1 = require("secp256k1"); // install via: npm install secp256k1

let privKey;
do {
  privKey = crypto.randomBytes(32);
} while (!secp256k1.privateKeyVerify(privKey));

const pubKey = secp256k1.publicKeyCreate(privKey, false);

const payer = "Alice";
const merchant = "MerchantX";
const amount = "100";
const claimedAmount = "100";

function padBytes(str, length) {
  const buf = Buffer.alloc(length);
  const strBuf = Buffer.from(str, "utf8");
  strBuf.copy(buf);
  return buf;
}

const payerBytes = padBytes(payer, 32);
const merchantBytes = padBytes(merchant, 32);
const amountBytes = padBytes(amount, 16);
const claimedAmountBytes = padBytes(claimedAmount, 16);
const separator = Buffer.from("|", "utf8");

const messageBuf = Buffer.concat([
  payerBytes,
  separator,
  merchantBytes,
  separator,
  amountBytes,
  separator,
  claimedAmountBytes,
]);

const msgHash = crypto.createHash("sha256").update(messageBuf).digest();

const { signature } = secp256k1.ecdsaSign(msgHash, privKey);

console.log("\n--- Noir Test Data ---\n");

console.log("Message bytes for hash:");
process.stdout.write("message: [");
for (let i = 0; i < messageBuf.length; i++) {
  process.stdout.write(
    "0x" + messageBuf[i].toString(16).padStart(2, "0") + ", "
  );
}
console.log("]\n");

console.log("Message hash (SHA256):");
process.stdout.write("msgHash: [");
for (let i = 0; i < msgHash.length; i++) {
  process.stdout.write("0x" + msgHash[i].toString(16).padStart(2, "0") + ", ");
}
console.log("]\n");

console.log("Message hash (bigint):");
console.log(BigInt("0x" + msgHash.toString("hex")));

const printBuf = (label, buf) => {
  console.log(`${label}: [`);
  for (let i = 0; i < buf.length; i++) {
    process.stdout.write("0x" + buf[i].toString(16).padStart(2, "0") + ", ");
  }
  console.log("]\n");
};

printBuf("payer_name", payerBytes);
printBuf("merchant_name", merchantBytes);
printBuf("amount", amountBytes);
printBuf("claimed_amount", claimedAmountBytes);

printBuf("signature", signature);

printBuf("pubkey_x", pubKey.slice(1, 33));
printBuf("pubkey_y", pubKey.slice(33, 65));
