# poqeth: Efficient, post-quantum signature verification on Ethereum
![image](https://github.com/user-attachments/assets/515b5975-a503-4cc0-8b32-e07f1fd91071)

This work explores the application and efficient deployment of (standardized) post-quantum (PQ) digital signature algorithms in the blockchain environment. Specifically, we implement and evaluate four PQ signatures in the Ethereum Virtual Machine: W-OTS
, XMSS, SPHINCS+, and MAYO. We focus on optimizing the gas costs of the verification algorithms as that is the signature schemes' only algorithm executed on-chain, thus incurring financial costs (transaction fees) for the users. Hence, the verification algorithm is the signature schemes' main bottleneck for decentralized applications.

We examine two methods to verify post-quantum digital signatures on-chain. Our practical performance evaluation shows that full on-chain verification is often prohibitively costly. Naysayer proofs (FC'24) allow a novel optimistic verification mode. We observe that the Naysayer verification mode is generally the cheapest, at the cost of additional trust assumptions. We release our implementation called poqeth as an open-source library.

[eprint](https://eprint.iacr.org/2025/091)


## For developers 

### Requirements
Ensure you have the following installed before proceeding:
- **Foundry**: Install the Foundry development toolkit using the command below:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  ```
**Node.js and npm**: Required for setting up dependencies.

**Git**: To clone this repository.


### Running Tests

To ensure the implementation is working as expected, run the test suite:

1. **Run Tests**:
  ```bash
     forge test
  ```

More information: https://book.getfoundry.sh/
