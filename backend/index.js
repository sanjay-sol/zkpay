const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { UltraHonkBackend } = require("@aztec/bb.js");
const fs = require("fs");
const path = require("path");

// Read circuit JSON from the same directory (adjust the path if needed)
const circuitPath = path.join(__dirname, "zkpay.json");
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"));

const app = express();
const port = 3000; // or any port you prefer

app.use(cors());

app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

// Endpoint to verify the proof
app.post("/verify", async (req, res) => {
  try {
    const { proof, publicInputs } = req.body;

    if (!proof) {
      return res
        .status(400)
        .json({ success: false, message: "No proof provided" });
    }

    console.log("Received proof for verification:");

    const backend = new UltraHonkBackend(circuit.bytecode);
    const proofBuffer = Buffer.from(proof, "base64");
    const publicInputsBuffer = Buffer.from(publicInputs, "base64");

    const isValid = await backend.verifyProof({
      proof: proofBuffer,
      publicInputs: publicInputsBuffer,
    });

    console.log("Proof verification result:", isValid);

    res.json({
      success: true,
      verified: isValid,
    });
  } catch (err) {
    console.error("Error verifying proof:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.listen(port, () => {
  console.log(`✅ Server listening on http://localhost:${port}`);
});
