# ZK Payment Proof Generator

A Zero-Knowledge (ZK) payment proof system built with Noir, demonstrating privacy-preserving verification of payments using ASN.1 encoded certificates.

---

## 📑 Table of Contents

- [ZK Payment Proof Generator](#zk-payment-proof-generator)
  - [📑 Table of Contents](#-table-of-contents)
  - [Proposal](#proposal)
  - [What is the Problem?](#what-is-the-problem)
  - [What is Our Solution?](#what-is-our-solution)
  - [Workflow diagram / Architecture](#workflow-diagram--architecture)
  - [What Noir is Missing](#what-noir-is-missing)
    - [🛠 ASN.1 Parser](#-asn1-parser)
  - [How to Set Up the Project](#how-to-set-up-the-project)
    - [🖥 Backend](#-backend)
    - [🌐 frontend](#-frontend)
  - [7️⃣ Future Plans](#7️⃣-future-plans)
    - [🚀 Project Roadmap](#-project-roadmap)
    - [🛠 ASN.1 Parser Development](#-asn1-parser-development)

---

##  Proposal

Along with this project our team also primarily proposes **implementing ASN.1 parsing capabilities into the Noir ecosystem** to handle real-world certificate formats (e.g., DER-encoded certificates from payment gateways).

🔗 **ASN.1 Parser Spec Sheet:**  
[ASN.1 Parser Proposal and Specification Sheet](https://hackmd.io/@sanjay-sol/SJlxosdexl)

🚀 **Live Frontend:**  
[https://zk-payment-proof.vercel.app](https://zk-payment-proof.vercel.app)

🖥  ** Demo Vide:**
[Loom](https://zk-payment-proof.vercel.app)\

📦 **Repository:**  
[https://github.com/sanjay-sol/zkpay](https://github.com/yourusername/zk-payment-proof)

---

## What is the Problem?

Today’s digital payments are typically **verified by revealing full transaction details** to third parties (e.g., merchants, employers, paymentId ..). This raises concerns over **privacy and data exposure.**

Key challenges:
- Need to **prove payment occurred** without sharing sensitive info.
- **Digital certificates (in ASN.1 format)** are the standard output of payment gateways, but they are **not natively parsable in Noir.**

---

## What is Our Solution?

We built a **Zero-Knowledge Payment Proof Generator** that allows users to:

- Upload an ASN.1 encoded payment certificate.
- Parse the certificate to extract payer, receiver, amount, payment ID, signature, and public key.
- Feed extracted data into a **Noir Zero-Knowledge circuit** that verifies the signature and generates a **ZK proof**.
- Allow organizations to verify the proof **without seeing full payment details.**

Example use cases:
- Prove you’ve paid for a **Netflix subscription** without showing your full bank statement.
- An employee can prove they received **salary payment** privately.

---

## Workflow diagram / Architecture

<img width="1275" alt="Screenshot 2025-05-09 at 12 01 42 AM" src="https://github.com/user-attachments/assets/96456d85-3641-4df5-9aeb-4400f055c24a" />


## What Noir is Missing

### 🛠 ASN.1 Parser

To fully enable this and similar use cases, **Noir must support ASN.1 parsing.**

🔗 **ASN.1 Parser Spec Sheet:**  
[ASN.1 Parser Proposal and Specification Sheet](https://hackmd.io/@sanjay-sol/SJlxosdexl)

Currently, developers must **pre-parse certificates outside of Noir**, breaking the privacy and trustless workflow. A native ASN.1 parser would unlock:
- Payment proofs
- Secure ID verification
- PKI-based authentication
- And more 🚀

---

## How to Set Up the Project

### 🖥 Backend

1. Clone the repo:
   ```bash
   git clone https://github.com/sanjay-sol/zkpay
   cd zkpay/backend

2. Install depencies
    ```bash 
    npm install

3. Run the server
    ```bash
    npm run dev

### 🌐 frontend

1. Clone the repo:
   ```bash
   git clone https://github.com/sanjay-sol/zkpay
   cd zkpay/frontend

2. Install depencies
    ```bash
    yarn

3. Run the server
    ```bash
     yarn dev


## 7️⃣ Future Plans

### 🚀 Project Roadmap

- Add more real-world payment gateway integrations (Stripe, Razorpay, etc.).
- Build a universal payment proof dashboard for verifiers.
- Extend the UI/UX for better onboarding and customization.
- Many more while building /......🚀🚀🚀🚀

### 🛠 ASN.1 Parser Development

- Collaborate with the Noir community to upstream ASN.1 parsing library.
- Full implementation of DER encoding/decoding inside Noir circuits.
- Publish ASN.1 helper utilities to abstract common parsing tasks.
- Many more ....🚀🚀🚀


