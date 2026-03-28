# BTSL Implementation Guide — Compiler and Validator Reference

This document is the technical reference for implementing a BTSL engine in any
programming language (`bdk` / Rust, `bitcoinjs-lib` / JavaScript, `libpsbt` / C++,
Python, etc.).

It defines the two fundamental data flows of the standard: **Construction** (Maker)
and **Verification** (Checker/Signer). Any failed step **immediately halts the
pipeline**. A partial result MUST NOT be exported as a valid PSBT.

> **Relationship to the specification:** This guide is a companion to the BTSL
> specification (§3–§5). All normative rules, error codes, and weight values cited
> here are authoritative in the specification. In case of conflict, the specification
> takes precedence.

---

## Part 1 — Construction Workflow (Maker Pipeline)

The goal of this workflow is to transform a `.bts` schema and user-provided parameters
into a binary PSBT ready to be shared. **The order of operations is strict and
non-negotiable** (§3.4 normative pipeline).

```
Step 1.1  Parse & Bind       — schema parsing, @PARAM resolution
Step 1.2  REF() Resolution   — on-chain network fetch
Step 1.3  calc Execution     — sequential variable evaluation
Step 1.4  ASSERT Evaluation  — full assertion check
Step 1.5  PSBT Construction  — buildInput / buildOutput
Step 1.6  Export             — Base64 / Hex serialization
```

---

### Step 1.1 — Parameter Binding

The compiler parses the `.bts` file and extracts all declared `@PARAMS`.

- Resolve top-level `CONST:` values first. Each `PSBT_SCHEMA` may also declare a
  local `CONST:` block whose scope is limited to that schema. Local constants
  override top-level constants of the same name within the schema scope.
- Read the `.params` file (UTF-8, `key=value`, one per line, `#` for comments).
- Map each key to the corresponding `@PARAM`. Missing `@PARAM` → `BTSL_ERR_04b`.
- Unrecognized key in `.params` → `BTSL_WARN_01`.
- Untyped `@PARAM` → `BTSL_WARN_03` (Flexible Mode).
- `btc` values normalized to `sats` (× 100,000,000) at this stage. All subsequent
  operations are performed exclusively on `SAT` integers.
- `@PARAM:Pubkey` values MUST be validated as 33-byte compressed secp256k1 public
  keys (prefix `0x02` or `0x03`). Invalid value → `BTSL_ERR_04e`.

#### `From()` Resolver (Binding-Phase UTXO Resolution)

When an input declares `utxo: From(@PUBKEY) AS alias`, the resolver executes at
bind time (step 2 of the normative pipeline, §3.4) — before `calc` or `REF()`.

1. **Validate** that `@PUBKEY` is declared as `@X:Pubkey` in `PARAMS:`. Any other
   type → `BTSL_ERR_04e`.
2. **Derive the address** from the public key:
   - If the input declares `native_input_type` (e.g., `NATIVE P2WPKH`), derive
     the address for that type.
   - If absent, derive P2TR key-path by default and emit `BTSL_WARN_08`.
3. **Query the indexer** for confirmed UTXOs at the derived address (list-query,
   distinct from the `REF()` point-query in Step 1.2).
4. **Select the largest** confirmed UTXO by amount (largest-first strategy).
   If no confirmed UTXO is found → `BTSL_ERR_09`.
5. **Register** the selected UTXO in the binding context under `alias`:
   - `alias.amount` — accessible in `calc` as a `SAT` integer (via `alias_ref`).
   - `alias.address` — accessible as an `address_ref` in `OUTPUTS` (via `alias_ref`).
   - The `txid:vout` MUST be persisted so the Checker can replay against the same UTXO.

From this point forward, `alias` behaves identically to a `@PARAM:UTXO` binding for
all subsequent pipeline phases.

> **`AS alias` is mandatory.** Omitting it is a syntax error (`BTSL_ERR_00`).
> `From()` is only valid in `simple_input_block`. Usage in `unlock_block`, `calc`,
> or `ASSERT` is a syntax error (`BTSL_ERR_00`).

---

### Step 1.2 — REF() Resolution (Network Fetch)

Before any calculation, the engine MUST possess the actual on-chain state.

For each `REF()` call in the schema:

| REF() form | Resolution |
|:---|:---|
| `REF(@PARAM.amount)` | Query indexer for the confirmed satoshi value of the UTXO bound to `@PARAM`. |
| `REF(SCHEMA:idx.amount)` | Query indexer for the confirmed output amount of a previously broadcast schema transaction. |

- If the target UTXO is unconfirmed or not found → `BTSL_ERR_05`.
- If the target is a `workflow_ref` whose parent has not been broadcast → mark the
  `calc` block as `Async-Ready` and defer. Forcing execution without confirmation →
  `BTSL_ERR_05`.

> **Important distinction:** A bare `workflow_ref` (e.g., `VAULT_DEPOSIT:0.amount`)
> used without `REF()` resolves from local workflow context and trusts the PSBT data.
> `REF(VAULT_DEPOSIT:0.amount)` forces an independent on-chain query and overrides
> any locally declared value. Always use `REF()` when the live blockchain value is
> required for security (§4.2).

---

### Step 1.3 — `calc` Execution

The engine resolves `calc` assignments **sequentially in declaration order**.

- Any reference to a `calc` variable not yet declared → `BTSL_ERR_04d`.
- The `fees` variable MUST use the reserved name `fees` for the implicit balance check
  to function (§3.8). Any other name causes the balance check to be skipped →
  `BTSL_WARN_06`.
- All arithmetic uses integer operations. Division is floor-truncated towards zero.
- Division by zero, integer overflow, or negative `SAT` result → `BTSL_ERR_08`.

**`vSize` computation** uses the canonical weight model (§3.5). Do not use wallet
runtime estimation. The full model is reproduced in Part 3 of this guide.

---

### Step 1.4 — ASSERT Evaluation

**After `calc` completes and before PSBT construction**, the engine evaluates all
`ASSERT` clauses. This is the enforcement gate: if any assertion fails, the PSBT is
never built.

- Assertions execute in numerical index order (0 to N).
- All assertions MUST be evaluated. Partial execution is prohibited.
- Any `false` condition → `BTSL_ERR_06`. Pipeline halts immediately.
- Non-sequential indices (gaps) → `BTSL_WARN_02` (execution continues in index order).

**Implicit balance check** (performed when `fees` is declared in `calc`):
```
SUM(INPUTS_onchain) == SUM(OUTPUTS) + fees
```
If the `calc` block contains a variable named `fees`, this invariant is checked.
Violation → `BTSL_ERR_06`. If no variable named `fees` exists in `calc`, the
balance check is skipped and `BTSL_WARN_06` MUST be emitted (§3.8).

**Dust check** (always performed):
For every output of type standard or `SCRIPT`: if `amount < DUST_LIMIT` → `BTSL_ERR_07`.

---

### Step 1.5 — PSBT Construction

The engine instantiates the PSBT object **natively** from the first instruction.
Building a raw transaction and converting to PSBT at the end is **non-compliant** and
defeats the co-signing purpose of the standard.

```python
# Language-agnostic pseudocode
psbt = new PSBT()                     # Native PSBT object — never a raw tx builder

for input_def in schema.INPUTS:
    psbt.addInput(buildInput(input_def, resolved_params))

for output_def in schema.OUTPUTS:
    psbt.addOutput(buildOutput(output_def, calc_results, resolved_params))
```

#### `buildInput` — Complete Dispatcher

The function MUST dispatch by input type. All five types defined in the grammar MUST
be handled:

```javascript
function buildInput(input_def, params) {
    // utxo_ref may be a @PARAM:UTXO key or a From() alias registered at bind time.
    // Both resolve identically in the binding context after Step 1.1.
    const utxo = params.get(input_def.utxo_ref);

    const base = {
        txid:     utxo.txid,
        vout:     utxo.vout,
        sequence: input_def.sequence ?? 0xFFFFFFFF,
    };

    switch (input_def.type) {

        // ── Native SegWit key-path inputs ──────────────────────────────
        case "NATIVE_P2WPKH":
        case "NATIVE_P2TR_KEY":
            return {
                ...base,
                witnessUtxo: {
                    script: utxo.scriptPubKey,   // hex-decoded
                    amount: BigInt(utxo.value),  // MUST use on-chain Blockchain_Value
                },
            };

        // ── Legacy input ────────────────────────────────────────────────
        // BIP174 requires the full raw transaction for P2PKH inputs.
        // This requires a SECOND distinct API fetch:
        //   GET <indexer>/tx/{txid}/raw  →  returns full tx hex
        case "NATIVE_P2PKH":
            return {
                ...base,
                nonWitnessUtxo: fetchRawTx(utxo.txid), // full tx bytes
            };

        // ── Script-hash spend (P2WSH) ───────────────────────────────────
        // witness_data may include <empty> placeholders (e.g., OP_CHECKMULTISIG
        // dummy element per BIP147). <empty> pushes a 0-byte item onto the
        // witness stack. Weight: 1 wu (varint encoding length 0).
        case "UNLOCK_P2WSH":
            return {
                ...base,
                witnessUtxo: {
                    script: utxo.scriptPubKey,
                    amount: BigInt(utxo.value),
                },
                witnessScript: compileAsm(
                    input_def.script_def.asm,
                    input_def.script_params
                ),
            };

        // ── Taproot script-path spend ───────────────────────────────────
        // control_block MUST be derived automatically — never user-provided.
        // Manual control_block input → BTSL_ERR_04a.
        case "UNLOCK_P2TR_SCRIPT":
            return {
                ...base,
                witnessUtxo: {
                    script: utxo.scriptPubKey,
                    amount: BigInt(utxo.value),
                },
                tapLeafScript: [{
                    leafVersion: input_def.script_def.leaf_version,
                    script:      compileAsm(
                                    input_def.script_def.asm,
                                    input_def.script_params
                                 ),
                    controlBlock: deriveControlBlock(
                                    input_def.script_def.tap_tree,
                                    input_def.script_def.internal_key
                                  ),
                }],
                tapInternalKey: input_def.script_def.internal_key,
            };

        default:
            throw new Error("BTSL_ERR_04c: Unrecognized input type — " + input_def.type);
    }
}
```

> **`deriveControlBlock` routine (automated):**
> 1. Retrieve `internal_key` and full `TapTree` from `SCRIPT_DEFS`.
> 2. Compute the TapTree Merkle root (BIP341).
> 3. Derive `TapTweak = taggedHash("TapTweak", internal_key || merkle_root)`.
> 4. Compute the tweaked output key.
> 5. For each leaf referenced in `UNLOCK`, compute the Merkle inclusion proof and
>    serialize: `[leaf_version | parity_bit] || internal_key || merkle_branch`.
>
> This derivation is deterministic from `SCRIPT_DEFS` and requires no user input.

#### `buildOutput` — Complete Dispatcher

```javascript
function buildOutput(output_def, calc_results, params) {

    switch (output_def.type) {

        // ── Standard address output ─────────────────────────────────────
        // address_ref: STRING, compile_ref, alias_ref, PASCAL_CASE_ID, or
        // IDENTIFIER (Formal Grammar in spec — lexer priority; bare snake_case_id invalid).
        // alias_ref (e.g. selected_utxo.address) resolves from the binding context.
        // amount may be a literal (sats) or a calc variable name.
        case "ADDRESS":
            return {
                address: resolveAddress(output_def.address_ref, params),
                amount:  BigInt(
                    calc_results.get(output_def.amount_var) ?? output_def.amount
                ),
            };

        // ── Change output ───────────────────────────────────────────────
        // amount MUST come from a calc variable — literals are forbidden (§4.1)
        case "CHANGE": {
            const changeAmount = calc_results.get(output_def.amount_var);
            if (changeAmount === undefined)
                throw new Error("BTSL_ERR_04b: CHANGE amount var not found in calc");
            if (changeAmount < 0n)
                throw new Error("BTSL_ERR_08: Negative CHANGE amount");
            return {
                address: resolveAddress(output_def.address_ref, params),
                amount:  BigInt(changeAmount),
            };
        }

        // ── Script output (e.g. vault deposit) ─────────────────────────
        case "SCRIPT":
            return {
                script: deriveScriptPubKey(
                    output_def.script_def,
                    output_def.script_params,
                    params
                ),
                amount: BigInt(
                    calc_results.get(output_def.amount_var) ?? output_def.amount
                ),
            };

        // ── OP_RETURN output ────────────────────────────────────────────
        case "OP_RETURN": {
            const payload = resolveHexData(output_def.hex_payload, params);
            if (payload.length > 80)
                console.warn("BTSL_WARN_04: OP_RETURN payload exceeds 80 bytes — " +
                             "may be rejected by Bitcoin Core ≤ v29 or Bitcoin Knots.");
            return {
                script: buildOpReturnScript(payload),
                amount: 0n,
            };
        }

        default:
            throw new Error("BTSL_ERR_04c: Unrecognized output type — " + output_def.type);
    }
}
```

---

### Step 1.6 — Export

The PSBT MUST NOT be exported before Steps 1.4 and 1.5 complete without fatal error.

```javascript
const psbtBytes  = psbt.toPSBT();        // BIP174/370 binary
const psbtBase64 = base64.encode(psbtBytes);
```

---

## Part 2 — Verification Workflow (Checker / Signer Pipeline)

This workflow is executed by any entity (hardware wallet, co-signer, independent
auditor) receiving a PSBT generated by a third party. Its goal is to
mathematically verify that the binary PSBT exactly matches the contract defined
by the schema.

**Required input (The Truth Triplet):**
1. `psbt_base64` — the binary transaction object
2. `schema.bts` — the BTSL schema file (normative reference)
3. `instance.params` — the runtime binding file

---

### Step 2.1 — Decode and Load

- Decode the PSBT binary into a readable structure (JSON or internal AST).
  Example: `bitcoin-cli decodepsbt` or equivalent native library call.
- Parse `schema.bts` into an AST (same Phase 0–1 as the Maker pipeline).
- Load and parse `instance.params` into the parameter map.

---

### Step 2.2 — Zero-Trust UTXO Restoration (Anti-Fraud Step)

This is the critical security step that defends against a malicious coordinator.

For **each input** in the decoded PSBT:

1. Extract `txid:vout`.
2. Query the indexer independently:
   ```
   GET <indexer>/tx/{txid}  →  extract vout[n].value and vout[n].scriptpubkey
   ```
3. **Override** the `amount` declared in `witness_utxo` / `non_witness_utxo` of
   the PSBT with the fetched `Blockchain_Value`. The PSBT-declared value MUST be
   treated as untrusted.
4. **Strict validation:** `PSBT_IN_VALUE == Blockchain_Value`. Any discrepancy
   is fatal — reject immediately.

> **Why this matters:** A malicious coordinator could declare a lower UTXO value in
> the PSBT's `witness_utxo` field, causing the fee calculation to be underestimated.
> The checker recomputing `calc` with the fraudulent value would approve an invalid
> transaction. The Zero-Trust rule eliminates this attack vector entirely.

**`From()` alias replay:** If the Maker used `From(@PUBKEY) AS alias`, the resolved
`txid:vout` is persisted in the binding context (`.params` effective state). The
Checker MUST load this persisted binding and verify the UTXO against the on-chain
indexer using the same Zero-Trust rule above. The Checker does NOT re-execute the
`From()` selection — it validates the specific UTXO that was bound (§4.5.5).

Structural checks (also in this step):
- Number of PSBT inputs matches `INPUTS` section count.
- Number of PSBT outputs matches `OUTPUTS` section count.
- Each input `scriptPubKey` matches the declared type (NATIVE or UNLOCK).
- Mismatch → `BTSL_ERR_01`.
- Anchored pubkey/script mismatch → `BTSL_ERR_02`.

---

### Step 2.3 — `calc` Replay

Re-execute the `calc` engine using:
- Parameters from `instance.params` (same as Maker).
- UTXO amounts from the certified on-chain values obtained in Step 2.2 (not from PSBT).

Store all resulting variables (`fees`, `change_amount`, `final_payout`, etc.).

---

### Step 2.4 — Cross-Validation and ASSERT

1. **Output amount cross-check:** For each output in the PSBT, compare the declared
   amount against the corresponding `calc` variable or literal in the schema.
   Any divergence is treated as an `ASSERT` failure → `BTSL_ERR_06`.

2. **ASSERT execution:** Evaluate all `ASSERT` clauses in numerical order using
   the replayed `calc` variables. All clauses MUST be evaluated.
   Any `false` → `BTSL_ERR_06`.

3. **Implicit balance check** (if `fees` variable exists in `calc`):
   ```
   SUM(INPUTS_onchain) == SUM(OUTPUTS_PSBT) + fees_calc
   ```
   Violation → `BTSL_ERR_06`. If `fees` is absent → `BTSL_WARN_06` (check skipped).

4. **Dust check:** Any standard or `SCRIPT` output `< DUST_LIMIT` → `BTSL_ERR_07`.

5. **Weight check:** If `tx_weight > 400,000 wu` → `BTSL_WARN_07`.

---

### Step 2.5 — Signature Authorization

```javascript
if (step22_passed && step23_passed && step24_passed) {
    // All checks passed — signing is authorized
    psbt.signInput(index, keyPair);   // wallet/HSM operation
    return { status: "AUTHORIZED" };
} else {
    throw new Error("BTSL_ERR_XX: " + failing_check);
}
```

**No partial signing is permitted.** Signing is authorized if and only if all
checks in Steps 2.2 through 2.4 pass without fatal error.

---

## Part 3 — Canonical Weight Model Reference

This section reproduces the normative weight tables from §3.5 of the specification.
Implementations MUST use these exact values. Do not use wallet runtime estimation.

### Formula

```
tx_weight = BASE_TX_OVERHEAD
          + SEGWIT_OVERHEAD          (conditional — see below)
          + Σ input_weight(input_i)
          + Σ output_weight(output_j)

vsize = ceil(tx_weight / 4)          (single rounding operation at the end)
```

### Transaction Overhead

| Constant | Value | Condition |
|:---|:---|:---|
| `BASE_TX_OVERHEAD` | 40 wu | Always present. `version`(4B) + `vin_count`(1B) + `vout_count`(1B) + `locktime`(4B) = 10B × 4. |
| `SEGWIT_OVERHEAD` | 2 wu | Present **if and only if** at least one input is segwit (P2WPKH, P2TR, P2WSH). SegWit `marker`(1B) + `flag`(1B) × weight factor 1. |

A pure-legacy transaction (all P2PKH inputs) uses only `BASE_TX_OVERHEAD = 40 wu`.

### Input Weight Table

All weights in **wu**. Non-witness bytes × 4. Witness bytes × 1.

The non-witness portion of any segwit input:
`prevout`(36B) + `scriptSig_len`(1B) + `scriptSig`(0B) + `nSequence`(4B) = 41B × 4 = **164 wu**.

| Type | Non-witness (wu) | Witness (wu) | Total (wu) |
|:---|:---|:---|:---|
| `P2PKH` | 592 wu *(148B × 4)* | 0 | **592 wu** |
| `P2WPKH` | 164 wu | 109 wu *(1B item_count + 1B sig_len + 73B sig + 1B pk_len + 33B pk)* | **273 wu** |
| `P2TR_KEY` | 164 wu | 66 wu *(1B item_count + 1B sig_len + 64B Schnorr sig)* | **230 wu** |
| `P2WSH` | 164 wu | `script_witness_weight` (sww) | **164 + sww wu** |
| `P2TR_SCRIPT` | 164 wu | `script_witness_weight` (sww) + `control_block_weight` (cbw) | **164 + sww + cbw wu** |

### Output Weight Table

Outputs contain no witness data. All bytes × 4.

| Type | Weight (wu) | Derivation |
|:---|:---|:---|
| `P2WPKH` | 124 wu | (8 + 1 + 22)B × 4 |
| `P2TR` | 172 wu | (8 + 1 + 34)B × 4 |
| `P2WSH` | 172 wu | (8 + 1 + 34)B × 4 |
| `P2PKH` | 136 wu | (8 + 1 + 25)B × 4 |
| `OP_RETURN` | `(11 + len(payload)) × 4` wu | For payload ≤ 75B |
| | `(12 + len(payload)) × 4` wu | For 76B ≤ payload ≤ 252B (OP_PUSHDATA1) |
| | `(13 + len(payload)) × 4` wu | For 253B ≤ payload ≤ 65535B (OP_PUSHDATA2) |

### Auxiliary Weight Formulas

```
script_witness_weight =
      1                                    (* varint: number of stack items *)
    + Σ (1 + size(witness_element_i))      (* varint(len) + element bytes   *)
    + 1 + len(serialized_script)           (* varint(script_len) + script   *)

placeholder_weight:
    <sig(...)>   → 74 wu   (* varint(1) + DER sig WCC 73B — ECDSA        *)
                   65 wu   (* varint(1) + Schnorr sig 64B — P2TR         *)
    <data(...)>  → MUST be declared in the schema (mandatory if used)
    <num(...)>   → 9 wu    (* varint(1) + up to 8B CScriptNum WCC        *)
    <empty>      → 1 wu    (* varint(0) — empty byte array, no payload   *)

control_block_weight(depth) = 34 + (32 × depth) wu
(*  1B varint + 1B leaf_version|parity + 32B internal_key + 32B×depth Merkle proof *)
```

### Validation Vectors

Implementations MUST produce these exact values:

| ID | Structure | Expected `tx_weight` | Expected `vsize` |
|:---|:---|:---|:---|
| WM-01 | 1 P2WPKH input, 1 P2WPKH output, 1 P2TR output | 42 + 273 + 124 + 172 = 611 wu | ceil(611/4) = 153 vB |
| WM-02 | 1 P2TR_KEY input, 1 P2TR output | 42 + 230 + 172 = 444 wu | ceil(444/4) = 111 vB |
| WM-03 | 1 P2PKH input, 1 P2PKH output (legacy) | 40 + 592 + 136 = 768 wu | ceil(768/4) = 192 vB |

> WM-01 and WM-02 include `SEGWIT_OVERHEAD = 2 wu` (at least one segwit input → 40 + 2 = 42 wu).
> WM-03 is pure legacy: `BASE_TX_OVERHEAD = 40 wu` only, no segwit overhead.

---

## Part 4 — Error and Warning Reference

### Error Codes

| Code | Name | Cause |
|:---|:---|:---|
| `BTSL_ERR_00` | `SYNTAX_ERROR` | Unparsable file: mixed indentation, missing `VERSION`, missing mandatory section, duplicate section. |
| `BTSL_ERR_01` | `TYPE_MISMATCH` | UTXO `scriptPubKey` does not match declared type (`NATIVE` or `UNLOCK`). Also raised if `sequence:` value is inconsistent with `OP_CSV` operand. |
| `BTSL_ERR_02` | `BINDING_FAILURE` | UTXO `scriptPubKey` does not match anchored `pubkey`/`script`. |
| `BTSL_ERR_03` | `CIRCULAR_DEPENDENCY` | Mutual `DEPENDS_ON` detected. |
| `BTSL_ERR_04a` | `INVALID_DERIVED_FIELD` | Manual input of a compiler-computed field (e.g., `control_block`). |
| `BTSL_ERR_04b` | `UNDECLARED_PARAM` | `@PARAM` referenced but not declared, or declared but unresolved. |
| `BTSL_ERR_04c` | `INVALID_SCRIPT_TYPE` | `.script_type` resolved to an unrecognized value, or unrecognized input/output type. |
| `BTSL_ERR_04d` | `FORWARD_REFERENCE_IN_CALC` | A `calc` variable references another `calc` variable not yet declared. |
| `BTSL_ERR_04e` | `INVALID_PUBKEY_PARAM` | A `Pubkey`-typed `@PARAM` received an invalid value (not 33-byte compressed key with prefix `0x02`/`0x03`), or `From()` was invoked on a `@PARAM` not declared as `Pubkey`. |
| `BTSL_ERR_05` | `UNRESOLVED_DEPENDENCY` | `REF()` or `SUM()` called on an unresolved or unbroadcast dependency. |
| `BTSL_ERR_06` | `ASSERT_FAILURE` | An `ASSERT` condition is false, or the implicit balance invariant is violated. |
| `BTSL_ERR_07` | `DUST_OUTPUT` | Output amount below `DUST_LIMIT` (546 sats default). |
| `BTSL_ERR_08` | `ARITHMETIC_ERROR` | Division by zero, integer overflow, or negative `SAT` result. |
| `BTSL_ERR_09` | `UTXO_RESOLUTION_FAILURE` | `From()` could not find any confirmed UTXO for the derived address of the given `Pubkey`. |

### Warning Codes

| Code | Name | Cause |
|:---|:---|:---|
| `BTSL_WARN_01` | `UNKNOWN_SECTION` | Unknown or reserved section encountered and ignored. |
| `BTSL_WARN_02` | `NON_SEQUENTIAL_ASSERT` | `ASSERT` indices have gaps. Execution proceeds in index order. |
| `BTSL_WARN_03` | `UNTYPED_PARAM` | `@PARAM` declared without type annotation. Flexible Mode fallback. |
| `BTSL_WARN_04` | `OP_RETURN_RELAY_RISK` | Payload > 80 bytes. May be rejected by Bitcoin Core ≤ v29 or Bitcoin Knots. |
| `BTSL_WARN_05` | `KEY_PATH_ENABLED` | Real (non-NUMS) key used as `internal_key` in a P2TR definition. Key-path spending is active. |
| `BTSL_WARN_06` | `MISSING_FEES_DECLARATION` | No `calc` variable named `fees`. Implicit balance check is skipped. |
| `BTSL_WARN_07` | `EXCEEDS_STANDARD_WEIGHT` | `tx_weight` > 400,000 wu. Transaction will likely be rejected by standard relay policy. |
| `BTSL_WARN_08` | `INFERRED_PUBKEY_TYPE` | `From()` used without `native_input_type`. Address type inferred as P2TR by default. Declare `NATIVE` explicitly for deterministic type binding. |

