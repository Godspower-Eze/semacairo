# Semaphore Cairo Verifier

This repository contains a full Cairo-native implementation of the Semaphore Verifier on Starknet. It verifies Groth16 proofs over the BN254 elliptic curve, allowing Semaphore identities to join groups and cast signals privately on Starknet.

## Overview

Semaphore is a zero-knowledge protocol that allows users to prove their membership in a group and send signals such as votes or endorsements without revealing their original identity.

This repository implements the Semaphore core logic, utilizing the [Garaga](https://github.com/keep-starknet-strange/garaga.git) library for the heavy cryptographic lifting required to verify Groth16 pairings over the BN254 curve in Cairo.

### Architecture: 12-Verifier Split

Due to Starknet's bytecode size limits (`< 80KB`), compiling all 32 supported Merkle tree depths into a single contract exceeds the maximum allowed size. To solve this, the verification logic is dynamically routed to **12 separate deployed verifier contracts**:

*   **Verifiers 1 to 8**: Handle Merkle tree depths `1` through `24` (3 depths per contract).
*   **Verifiers 9 to 12**: Handle Merkle tree depths `25` through `32` (2 depths per contract).

The main `Semaphore` contract takes an array of the 12 verifier addresses in its constructor and acts as a dynamic router. When `verify_proof` is called with a specific Merkle tree `depth`, the Semaphore contract automatically computes the index and delegates the call to the appropriate verifier component.

## Repository Structure

```tree
.
├── semacairo/
│   ├── Scarb.toml               # Scarb package configuration
│   ├── deploy.sh                # Deployment script for all contracts
│   ├── split_verifier.py        # Python script to generate the 12 verifiers
│   └── src/
│       ├── lib.cairo            
│       ├── semaphore.cairo      # Main routing contract and group management
│       ├── semaphore_verifier_interface.cairo # The verifier interface definition
│       ├── groth16_verifier_*.cairo # The 12 generated verifier contracts 
│       └── g16v_*_constants.cairo   # Mathematical constants for SNARK verifiers
└── verification_keys/           # Serialized verification keys for all 32 depths
```

## Prerequisites

*   **Scarb** (`v2.14.0`)
*   **Starknet Foundry** (`snforge` & `sncast`)

## Building and Testing

Navigate to the cairo project directory:

```bash
cd semacairo
```

Build the project:

```bash
scarb build
```

Run tests using Starknet Foundry:

```bash
snforge test
```

## Deployment

A helper bash script is provided to automate the sequential deployment of all 12 nested verifiers, followed by the deployment of the main Semaphore routing contract. 

Ensure you have your environment variables or keystores configured for `sncast` before proceeding.

```bash
cd semacairo
./deploy.sh
```

### Script Workflow:
1. Iterates from `1` to `12`, declaring and deploying `Semaphore_Groth16VerifierBN254_N`.
2. Uses a `sleep` mechanism for class hashes to be indexed by testnet RPCs to avoid deployment failure.
3. Keeps track of the 12 generated contract addresses.
4. Declares and deploys the main `Semaphore` contract, passing the 12 addresses as `Span<ContractAddress>` calldata into the constructor.

## Supported Depths

The protocol supports arbitrary depths ranging from `1` to `32`. Trying to verify a depth outside of these bounds will result in a panic.
