const crypto = require("crypto");
const fs = require("fs");

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});

fs.writeFileSync(
  "private.pem",
  privateKey.export({ type: "pkcs8", format: "pem" })
);
fs.writeFileSync(
  "public.pem",
  publicKey.export({ type: "spki", format: "pem" })
);

console.log("Keys saved to private.pem and public.pem");
