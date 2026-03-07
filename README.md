# Bitcoin Transaction Schema Language (BTSL)

BTSL is a declarative, "Policy-as-Code" language designed to formalize PSBTv2 (BIP370) workflows. It moves beyond raw transaction construction by defining a contract—the `.bts` schema—that acts as an authoritative, machine-verifiable implementation guide.

## Design Goals
BTSL was built to solve the fragility of imperative transaction building by enforcing:
- **Auditability:** Business rules (`calc`) and security invariants (`ASSERT`) are embedded in the schema.
- **Zero-Trust Validation:** The schema acts as a formal implementation guide, allowing any auditor to re-verify logic against on-chain data.
- **Cryptographic Binding:** Roles are cryptographically linked to UTXOs via public keys or scripts, preventing role substitution.
- **Workflow Chaining:** Formalizing multi-PSBT workflows via `DEPENDS_ON` and explicit outpoint binding.

## Documentation
- **[Specification v1.1](./spec/btsl_spec_v1.1.md)**: Full EBNF grammar, runtime semantics, and security considerations.
- **[Test Suite](./tests/test_vectors.md)**: Structural, logical, and cryptographic test vectors.

## Playground: Scenarios of Experimentation
The `/examples` folder contains "Scenario-based" schemas designed to test specific parts of the BTSL runtime:
- `TRICOUNT.bts`: Shared settlement with multi-party fee balancing.
- `MULTISIG.bts`: 2-of-2 multisig workflow and witness binding.
- `VAULT.bts`: Time-locked vault with multi-PSBT chaînage and CSV enforcement.
- `BRC20_DEPLOY.bts`: Data anchoring with `HEX_DATA` payloads.

## Implementation Checklist & Get Involved
This project is an open proposal for formal transaction validation. If you are building tools for coordination, PSBT handling, or auditing, you are invited to use these `.bts` files to test your own implementations.

**Implementation Checklist:**
- [ ] **Lexer/Parser:** INDENT/DEDENT handling + unit normalization (btc → sats).
- [ ] **Runtime:** WCC estimation for `vSize()`, `REF()` on-chain resolution, and `SUM(INPUTS)` global logic.
- [ ] **Binding:** Cryptographic validation of `scriptPubKey` vs roles.
- [ ] **Error Handling:** Full implementation of `BTSL_ERR_01` through `07`.

## Security & Limitations
BTSL assumes a Zero-Trust audit model. 
- **Risk Note:** In the absence of `BIP118` (SIGHASH_ANYPREVOUT) or `BIP119` (CTV), there is no complete mitigation against `txid` mutation of a parent transaction via RBF. BTSL considers this structural risk as accepted and recommends using `nLocktime` (anchoring at block height) and CPFP for transaction chaining.

> This is an **experimental prototype**, not a finished standard. I am stepping back from active Bitcoin development, so I am publishing these specs, grammar (EBNF), and test vectors as a foundation for anyone interested in experimenting with formal transaction validation.

If you find this approach useful for your own work or implementations, please feel free to fork or adapt it.

### License
MIT License.
