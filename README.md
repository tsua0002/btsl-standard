# Bitcoin Transaction Schema Language (BTSL)

BTSL is a declarative, "Policy-as-Code" language designed to formalize PSBTv2 (BIP370) workflows. It moves beyond raw transaction construction by defining a contract—the `.bts` schema—that acts as an authoritative, machine-verifiable implementation guide.

## Design Goals
BTSL was built to solve the fragility of imperative transaction building by enforcing:
- **Auditability:** Business rules (`calc`) and security invariants (`ASSERT`) are embedded in the schema.
- **Zero-Trust Validation:** The schema acts as a formal implementation guide, allowing any auditor to re-verify logic against on-chain data.
- **Cryptographic Binding:** Roles are cryptographically linked to UTXOs via public keys or scripts, preventing role substitution.
- **Workflow Chaining:** Formalizing multi-PSBT workflows via `DEPENDS_ON` and explicit outpoint binding.

## Documentation
- **[Specification v1.0](./spec/btsl-spec-v1.0.md)**: Full EBNF grammar, runtime semantics, test vectors, and security considerations.
- **[Implementation Guide v1.0](./spec/btsl-implementation-guide-v1.0.md)**: Step‑by‑step compiler and validator reference.

## Playground: Scenarios of Experimentation
The `/examples` folder contains "Scenario-based" schemas designed to test specific parts of the BTSL runtime:
- `TRICOUNT.bts`: Shared settlement with multi-party fee balancing.
- `MULTISIG.bts`: 2-of-2 multisig workflow and witness binding.
- `VAULT.bts`: Time-locked vault with multi-PSBT chaînage and CSV enforcement.
- `BRC20_DEPLOY.bts`: Data anchoring with `HEX_DATA` payloads.

## Implementation Checklist & Get Involved
This project defines **BTSL v1.0**, a proposed standard for formal PSBT construction and verification. If you are building tools for coordination, PSBT handling, or auditing, you are invited to:

- Implement a BTSL engine following the **Specification v1.0** and the **Implementation Guide v1.0**.
- Use the normative examples (§6) and test vectors (§7) in the specification as compliance targets.

**Implementation Checklist (high level):**
- [ ] **Lexer/Parser:** INDENT/DEDENT handling, reserved keywords, `.params` format, unit normalization (btc → sats).
- [ ] **Runtime:** Canonical weight model for `vSize()`, `REF()` on-chain resolution, and `SUM(INPUTS)` / `SUM(OUTPUTS)` global logic.
- [ ] **Binding:** Cryptographic validation of `scriptPubKey` vs anchored keys/scripts; `From(@PUBKEY) AS alias` resolver.
- [ ] **Error Handling:** Full implementation of `BTSL_ERR_00` through `BTSL_ERR_09` (including `04a`–`04e`) and `BTSL_WARN_01` through `BTSL_WARN_08`.

## Security & Limitations
BTSL assumes a Zero-Trust audit model.
- **Residual Risk:** In the absence of `BIP118` (SIGHASH_ANYPREVOUT) or `BIP119` (CTV), there is no complete mitigation against `txid` mutation of a parent transaction via RBF. BTSL considers this structural risk as accepted and recommends using `nLocktime` (anchoring at block height) and CPFP for transaction chaining (see §5.1.3).

If you find this approach useful for your own work or implementations, please feel free to fork, implement, or adapt it. Contributions and reviews are welcome via issues and pull requests.

### License
MIT License.
