# Blockchain-Based Temporary Vehicle Access Credential Prototype

Reference implementation of the temporary vehicle access credential scheme used for the experimental evaluation.

## Overview

The prototype combines:

- DID-based vehicle and driver identifiers
- Signed temporary QR credentials
- Blockchain-based credential state
- Expiration enforcement
- Geofence verification
- Replay prevention
- Credential revocation
- DID key rotation
- Vehicle-driver-plate binding

The repository also includes two comparison baselines:

1. Symmetric-key JWT baseline
2. Smart-contract baseline without DID

## Project Structure

```text
.
├── contracts/
│   └── QRAccess.sol
├── test/
│   ├── security-test.js
│   ├── security-evaluation.js
│   ├── jwt-baseline.js
│   └── blockchain-baseline.js
├── results/
│   ├── security-evaluation.csv
│   ├── jwt-baseline.csv
│   └── blockchain-baseline.csv
├── output/
│   └── temporary-credential.png
├── backend.js
├── did.js
├── hardhat.config.js
├── package.json
└── package-lock.json
```

## Smart Contract Authorization

`QRAccess.sol` uses the following authorization model:

| Function | Authorized caller | Purpose |
|---|---|---|
| `issueQR()` | Contract owner | Register a new credential |
| `revokeQR()` | Contract owner | Revoke a credential |
| `useQR()` | Authorized verifier | Mark a credential as used |
| `getQR()` | Anyone (read-only) | Retrieve credential state |
| `setVerifier()` | Contract owner | Add/remove authorized verifier |

The deploying account becomes the contract owner and an initial authorized verifier.

## Credential Verification

The backend verifies:

1. Digital signature
2. Expiration time
3. Registered truck-driver-plate binding
4. Geofence
5. On-chain credential hash
6. On-chain nonce
7. Credential ID derived from the nonce
8. Revocation status
9. Previous-use status

After successful verification, `useQR()` records the credential as used.

## Installation

```bash
npm install
npx hardhat compile
```

## Security Evaluation

Run:

```bash
npx hardhat run test/security-evaluation.js
```

The evaluation covers:

- Expiry enforcement
- Replay prevention
- Out-of-geofence detection
- Revocation
- Payload tampering
  - expiration
  - truck DID
  - driver DID
  - plate number
  - nonce
- DID key rotation

Results are written to:

```text
results/security-evaluation.csv
```

## JWT Baseline

The implemented JWT baseline uses:

- HS256 symmetric-key signing
- 60-second token expiration
- Centralized in-memory replay blacklist

Run:

```bash
node test/jwt-baseline.js
```

Results:

```text
results/jwt-baseline.csv
```

The blacklist-reset experiment specifically evaluates loss of centralized replay state. It should not be interpreted as a general limitation of JWT.

## Smart-Contract Baseline Without DID

This baseline uses ordinary application identifiers (`truckId` and `driverId`) while credential issuance, usage, and revocation are maintained on-chain.

Run:

```bash
npx hardhat run test/blockchain-baseline.js
```

Results:

```text
results/blockchain-baseline.csv
```

Only implemented properties are experimentally evaluated. DID identity and key-management differences are treated as architectural differences rather than measured security results.

## Notes

This repository is a compact reference implementation intended to reproduce the security mechanisms and experiments described in the study. It is not a production deployment.