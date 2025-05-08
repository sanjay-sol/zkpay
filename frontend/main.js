import { UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import circuit from "../target/zkpay.json";

let witness = null;
let backend = null;
let proof = null;
let publicInputs = null;

//! Sample data parsed from the Paypal cerrtificate from this data usin node-forge

/* var certURL =
  "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-a5cafa77";
var transmissionId = "103e3700-8b0c-11e6-8695-6b62a8a99ac4";
var transmissionSignature =
  "t8hlRk64rpEImZMKqgtp5dlWaT1W8ed/mf8Msos341QInVn3BMQubjAhM/cKiSJtW07VwJvSX7X4+YUmHBrm5BQ+CEkClke4Yf4ouhCK6GWsfs0J8cKkmjI0XxfJpPLgjROEWY3MXorwCtbvrEo5vrRI2+TyLkquBKAlM95LbNWG43lxMu0LHzsSRUBDdt5IP1b2CKqbcEJKGrC78iw+fJEQGagkJAiv3Qvpw8F/8q7FCQAZ3c81mzTvP4ZH3Xk2/nNznEA7eMi3u1EjSpTmLfAb423ytX37Ts0QpmPNgxJe8wnMB/+fvt4xjYH6KNe+bIcYU30hUIe9O8c9UFwKuQ==";
var transmissionTimestamp = "2016-10-05T14:57:40Z";
var headers = {
  "paypal-auth-algo": "SHA256withRSA",
  "paypal-cert-url": certURL,
  "paypal-transmission-id": transmissionId,
  "paypal-transmission-sig": transmissionSignature,
  "paypal-transmission-time": transmissionTimestamp,
};

var eventBody =
  '{"id":"WH-82L71649W50323023-5WC64761VS637831A","event_version":"1.0","create_time":"2016-10-05T14:57:40Z","resource_type":"sale","event_type":"PAYMENT.SALE.COMPLETED","summary":"Payment completed for $ 6.01 USD","resource":{"id":"8RS6210148826604N","state":"completed","amount":{"total":"6.01","currency":"USD","details":{"subtotal":"3.00","tax":"0.01","shipping":"1.00","handling_fee":"2.00","shipping_discount":"3.00"}},"payment_mode":"INSTANT_TRANSFER","protection_eligibility":"ELIGIBLE","protection_eligibility_type":"ITEM_NOT_RECEIVED_ELIGIBLE,UNAUTHORIZED_PAYMENT_ELIGIBLE","transaction_fee":{"value":"0.47","currency":"USD"},"invoice_number":"","custom":"Hello World!","parent_payment":"PAY-11X29866PC6848407K72RIQA","create_time":"2016-10-05T14:57:18Z","update_time":"2016-10-05T14:57:26Z","links":[{"href":"https://api.sandbox.paypal.com/v1/payments/sale/8RS6210148826604N","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/payments/sale/8RS6210148826604N/refund","rel":"refund","method":"POST"},{"href":"https://api.sandbox.paypal.com/v1/payments/payment/PAY-11X29866PC6848407K72RIQA","rel":"parent_payment","method":"GET"}]},"links":[{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-82L71649W50323023-5WC64761VS637831A","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-82L71649W50323023-5WC64761VS637831A/resend","rel":"resend","method":"POST"}]}';

var webhookId = "3TR748995U920805P";
*/

const sampleInput = {
  payer: "GeneralElectric",
  receiver: "Ferguson",
  amount: 166000,
  paymentId: "SRN9375802855",
};
const sampleData = {
  message: [
    0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x45, 0x6c, 0x65, 0x63, 0x74,
    0x72, 0x69, 0x63, 0x7c, 0x46, 0x65, 0x72, 0x67, 0x75, 0x73, 0x6f, 0x6e,
    0x7c, 0x31, 0x36, 0x36, 0x30, 0x30, 0x30, 0x7c, 0x53, 0x52, 0x4e, 0x39,
    0x33, 0x37, 0x35, 0x38, 0x30, 0x32, 0x38, 0x35, 0x35, 0x7c,
  ],

  msg_hash: [
    0xe3, 0xa6, 0x26, 0x68, 0x19, 0xf3, 0x4d, 0xd1, 0xaf, 0x14, 0x7c, 0x47,
    0x91, 0xd4, 0xef, 0x92, 0x41, 0xd9, 0xe3, 0xf8, 0x07, 0xc6, 0xb3, 0x40,
    0xe7, 0x94, 0x42, 0x8d, 0x6b, 0x8e, 0xba, 0x7a,
  ],

  signature: [
    0x12, 0x8e, 0xcc, 0x34, 0xd9, 0xca, 0x40, 0xa6, 0x56, 0xcd, 0x2b, 0x53,
    0x74, 0xe7, 0x37, 0xda, 0x0c, 0x41, 0x84, 0x8e, 0x17, 0x45, 0x96, 0xbb,
    0xd0, 0xec, 0x6d, 0x94, 0xdf, 0xb1, 0xf2, 0x05, 0x55, 0x3c, 0x7a, 0xe7,
    0x5d, 0x26, 0x7c, 0x93, 0xdf, 0xc7, 0x4f, 0xb2, 0x17, 0x9c, 0x3e, 0x6d,
    0x4b, 0x25, 0x27, 0x64, 0x73, 0xee, 0x66, 0x92, 0xa4, 0x4d, 0xab, 0x0e,
    0x85, 0x3b, 0x8d, 0xba,
  ],

  pubkey_x: [
    0xab, 0x8f, 0x04, 0x5d, 0x2f, 0xdc, 0x31, 0x88, 0x0e, 0x6c, 0x7b, 0x54,
    0x03, 0x94, 0x2c, 0x0e, 0xb1, 0x56, 0x2b, 0xa5, 0xd3, 0x1e, 0x3b, 0xb5,
    0x1e, 0x7f, 0x68, 0x74, 0xae, 0xd2, 0x94, 0x90,
  ],

  pubkey_y: [
    0x82, 0x1d, 0x6d, 0xba, 0x2d, 0xa8, 0xc0, 0xaa, 0xd7, 0xef, 0x51, 0x64,
    0x65, 0xb8, 0xc2, 0x8a, 0x72, 0x78, 0x2e, 0x9e, 0xe6, 0x2d, 0x96, 0x72,
    0xa9, 0x8e, 0xff, 0xeb, 0x8d, 0x07, 0xf9, 0x5b,
  ],
};

function setStatusLoading(statusId) {
  const statusDiv = document.getElementById(statusId);
  statusDiv.innerHTML = `
    <svg class="animate-spin h-6 w-6 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
    </svg>
  `;
}

function setStatusDone(statusId) {
  const statusDiv = document.getElementById(statusId);
  statusDiv.innerHTML = `
    <svg class="h-6 w-6 text-green-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
    </svg>
  `;
}

function clearStatus(statusId) {
  const statusDiv = document.getElementById(statusId);
  statusDiv.innerHTML = "";
}
document.getElementById("loadSampleBtn").addEventListener("click", async () => {
  setStatusLoading("loadSampleStatus");

  // existing logic...
  document.getElementById("payer").value = JSON.stringify(sampleInput.payer);
  document.getElementById("rec").value = JSON.stringify(sampleInput.receiver);
  document.getElementById("amount").value = JSON.stringify(sampleInput.amount);
  document.getElementById("payment").value = JSON.stringify(
    sampleInput.paymentId
  );

  document.getElementById("msgHash").value = JSON.stringify(
    sampleData.msg_hash
  );
  document.getElementById("signature").value = JSON.stringify(
    sampleData.signature
  );
  document.getElementById("pubkeyX").value = JSON.stringify(
    sampleData.pubkey_x
  );
  document.getElementById("pubkeyY").value = JSON.stringify(
    sampleData.pubkey_y
  );

  console.log("Sample certificate loaded");

  const noir = new Noir(circuit);
  const result = await noir.execute(sampleData);
  witness = result.witness;
  backend = new UltraHonkBackend(circuit.bytecode);

  console.log("Witness ready");

  setStatusDone("loadSampleStatus");
});

document
  .getElementById("generateProofBtn")
  .addEventListener("click", async () => {
    setStatusLoading("generateProofStatus");

    if (!witness || !backend) {
      console.log("Please load a certificate first.");
      clearStatus("generateProofStatus");
      return;
    }
    console.log("Generating proof...");
    ({ proof, publicInputs } = await backend.generateProof(witness));
    console.log("Proof generated:", proof);

    setStatusDone("generateProofStatus");
  });

document
  .getElementById("verifyProofBtn")
  .addEventListener("click", async () => {
    setStatusLoading("verifyProofStatus");

    if (!proof) {
      console.log("No proof to verify.");
      clearStatus("verifyProofStatus");
      return;
    }

    try {
      const proofBase64 = btoa(String.fromCharCode(...new Uint8Array(proof)));
      const publicInputsBase64 = btoa(
        String.fromCharCode(...new Uint8Array(publicInputs))
      );

      const response = await fetch("http://localhost:3000/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          proof: proofBase64,
          publicInputs: publicInputsBase64,
        }),
      });

      const data = await response.json();
      console.log("Backend verification response:", data);
      setStatusDone("verifyProofStatus");
    } catch (err) {
      console.error("Error verifying proof with backend:", err);
      clearStatus("verifyProofStatus");
    }
  });
