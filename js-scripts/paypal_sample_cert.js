const https = require("https");
const crypto = require("crypto");

const certURL =
  "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-a5cafa77";
const transmissionId = "103e3700-8b0c-11e6-8695-6b62a8a99ac4";
const transmissionSignature =
  "t8hlRk64rpEImZMKqgtp5dlWaT1W8ed/mf8Msos341QInVn3BMQubjAhM/cKiSJtW07VwJvSX7X4+YUmHBrm5BQ+CEkClke4Yf4ouhCK6GWsfs0J8cKkmjI0XxfJpPLgjROEWY3MXorwCtbvrEo5vrRI2+TyLkquBKAlM95LbNWG43lxMu0LHzsSRUBDdt5IP1b2CKqbcEJKGrC78iw+fJEQGagkJAiv3Qvpw8F/8q7FCQAZ3c81mzTvP4ZH3Xk2/nNznEA7eMi3u1EjSpTmLfAb423ytX37Ts0QpmPNgxJe8wnMB/+fvt4xjYH6KNe+bIcYU30hUIe9O8c9UFwKuQ==";
const transmissionTime = "2016-10-05T14:57:40Z";
const webhookId = "3TR748995U920805P";
const eventBody =
  '{"id":"WH-82L71649W50323023-5WC64761VS637831A","event_version":"1.0","create_time":"2016-10-05T14:57:40Z","resource_type":"sale","event_type":"PAYMENT.SALE.COMPLETED","summary":"Payment completed for $ 6.01 USD","resource":{"id":"8RS6210148826604N","state":"completed","amount":{"total":"6.01","currency":"USD","details":{"subtotal":"3.00","tax":"0.01","shipping":"1.00","handling_fee":"2.00","shipping_discount":"3.00"}},"payment_mode":"INSTANT_TRANSFER","protection_eligibility":"ELIGIBLE","protection_eligibility_type":"ITEM_NOT_RECEIVED_ELIGIBLE,UNAUTHORIZED_PAYMENT_ELIGIBLE","transaction_fee":{"value":"0.47","currency":"USD"},"invoice_number":"","custom":"Hello World!","parent_payment":"PAY-11X29866PC6848407K72RIQA","create_time":"2016-10-05T14:57:18Z","update_time":"2016-10-05T14:57:26Z","links":[{"href":"https://api.sandbox.paypal.com/v1/payments/sale/8RS6210148826604N","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/payments/sale/8RS6210148826604N/refund","rel":"refund","method":"POST"},{"href":"https://api.sandbox.paypal.com/v1/payments/payment/PAY-11X29866PC6848407K72RIQA","rel":"parent_payment","method":"GET"}]},"links":[{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-82L71649W50323023-5WC64761VS637831A","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-82L71649W50323023-5WC64761VS637831A/resend","rel":"resend","method":"POST"}]}';

const fetchCert = (url) => {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      })
      .on("error", (err) => reject(err));
  });
};

const pemToModExp = (pem) => {
  const x509 = new crypto.X509Certificate(pem);
  const pubKey = x509.publicKey;
  const der = pubKey.export({ format: "der", type: "spki" });
  const asn1 = crypto
    .createPublicKey({ key: pem, format: "pem" })
    .export({ format: "jwk" });
  const modulus = Buffer.from(asn1.n, "base64");
  const exponent = Buffer.from(asn1.e, "base64");
  return { modulus, exponent };
};

(async () => {
  try {
    const certPem = await fetchCert(certURL);

    const { modulus, exponent } = pemToModExp(certPem);

    const signatureBytes = Buffer.from(transmissionSignature, "base64");

    const bodyHash = crypto
      .createHash("sha256")
      .update(eventBody, "utf8")
      .digest("hex");
    const expectedSigString = `${transmissionId}|${transmissionTime}|${webhookId}|${bodyHash}`;
    const msgHash = crypto
      .createHash("sha256")
      .update(expectedSigString, "utf8")
      .digest();

    console.log("\nlet modulus: [u8; 256] = [");
    console.log(
      [...modulus].map((b) => `0x${b.toString(16).padStart(2, "0")}`).join(", ")
    );
    console.log("];\n");

    console.log("let exponent: [u8; 4] = [");
    console.log(
      [...exponent]
        .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
        .join(", ")
    );
    console.log("];\n");

    console.log("let signature: [u8; 256] = [");
    console.log(
      [...signatureBytes]
        .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
        .join(", ")
    );
    console.log("];\n");

    console.log("let msg_hash: [u8; 32] = [");
    console.log(
      [...msgHash].map((b) => `0x${b.toString(16).padStart(2, "0")}`).join(", ")
    );
    console.log("];");
  } catch (err) {
    console.error("Error:", err);
  }
})();
