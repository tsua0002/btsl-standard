# BTSL v1.0 — Checker verification predicates (reference annex)

**Status:** Accompanies the [Specification v1.0](./btsl-spec-v1.0.md). **Normative** definitions of phases, predicates **S-1…A-5**, and error codes are in **§9.3.1** of that document. This annex is a **consolidated implementer’s reference** (audit trail from the v1.0 finalization review).

**Date:** April 2026

---

## Predicate reference (aligned with §9.3.1)

For a PSBT **P**, schema **S**, parameters **Π**, and chain state:

**Implementation freedom:** any implementation that evaluates all predicates
correctly is compliant, regardless of internal architecture. The standard
defines **what** to verify, not **how** to implement verification.

═══════════════════════════════════════════════════════════════════════
 SHAPE PREDICATES — fast-fail before any per-field check
═══════════════════════════════════════════════════════════════════════

S-1 (input count):
  |P.inputs| == |S.INPUTS|
  → failure: BTSL_ERR_13 (SCHEMA_MISMATCH)

S-2 (output count):
  |P.outputs| == |S.OUTPUTS|
  → failure: BTSL_ERR_13 (SCHEMA_MISMATCH)

If S-1 or S-2 fails, the Checker MUST halt immediately.
No per-field or algebraic predicate is evaluated.

═══════════════════════════════════════════════════════════════════════
 INPUT PREDICATES — for each input i ∈ [0, |S.INPUTS|)
═══════════════════════════════════════════════════════════════════════

I-1 (ownership / type match):
  The scriptPubKey of the UTXO spent by P.inputs[i] MUST be derivable
  from resolve(S.INPUTS[i].utxo_ref, Π) for the declared input type.
  - NATIVE P2WPKH:      scriptPubKey == P2WPKH(hash160(pubkey))
  - NATIVE P2TR_KEY:    scriptPubKey == P2TR(pubkey)
  - NATIVE P2PKH:       scriptPubKey == P2PKH(hash160(pubkey))
  - UNLOCK P2WSH:       scriptPubKey == P2WSH(sha256(compiled_script))
  - UNLOCK P2TR_SCRIPT: scriptPubKey == P2TR(tweaked_key(internal_key, tap_tree))
  → failure: BTSL_ERR_01 (type mismatch) or BTSL_ERR_02 (binding failure)

I-2 (input binding):
  The txid:vout of P.inputs[i] MUST match the resolved UTXO reference.

  Case A — @PARAM:UTXO (explicit outpoint in params):
    P.inputs[i].txid == Π[@UTXO_REF].txid
    P.inputs[i].vout == Π[@UTXO_REF].vout
    → failure: BTSL_ERR_12 (OUTPOINT_MISMATCH)

  Case B — From(@PUBKEY) without effective params persisted:
    Relaxed to I-1 ownership check. The Checker verifies that the UTXO
    belongs to @PUBKEY for the declared type, but does not require a
    specific txid:vout. Any UTXO satisfying I-1 + I-3 + all A-* is valid.

  Case C — workflow_ref (DEPENDS_ON schema):
    P.inputs[i].txid == broadcast_txid(PARENT_SCHEMA)
    P.inputs[i].vout == declared_output_index
    If the parent is not broadcast / unavailable → BTSL_ERR_05 (UNRESOLVED_DEPENDENCY).
    If the parent is confirmed but the PSBT outpoint does not match → BTSL_ERR_12 (OUTPOINT_MISMATCH). See §9.4.

  Note on Case B vs Case A: if the Maker has persisted effective params
  (Binding Persistence Level 1 — see below), Case A applies and provides
  strict outpoint verification. If only brut params are available,
  Case B applies (ownership-only). The Truth Triplet accepts either form.

I-3 (zero-trust amount):
  The amount declared in P.inputs[i] (witnessUtxo or nonWitnessUtxo)
  MUST equal the independently fetched on-chain value.
    P.inputs[i].declared_amount == ChainValue(P.inputs[i].txid, P.inputs[i].vout)
  This step defends against a malicious coordinator injecting a fraudulent
  UTXO value in the PSBT's witnessUtxo field.
  → failure: BTSL_ERR_11 (PREVOUT_VALUE_MISMATCH)

I-4 (sequence, if declared in schema):
  If S.INPUTS[i] declares a sequence: field:
    P.inputs[i].nSequence == S.INPUTS[i].sequence
  The value MUST also be consistent with the OP_CSV operand in the
  associated asm: block (spec §9.5).
  → failure: BTSL_ERR_01 (TYPE_MISMATCH)

═══════════════════════════════════════════════════════════════════════
 OUTPUT PREDICATES — for each output j ∈ [0, |S.OUTPUTS|)
═══════════════════════════════════════════════════════════════════════

O-1 (destination):
  The scriptPubKey of P.outputs[j] MUST match the script derived from
  the schema output definition. Dispatch by output type:

  Case ADDRESS or CHANGE:
    expected = addressToScriptPubKey(
      resolveAddress(S.OUTPUTS[j].address_ref, Π, calc_vars, consts)
    )
    P.outputs[j].scriptPubKey == expected

  Case SCRIPT:
    expected = deriveScriptPubKey(
      S.OUTPUTS[j].script_def,
      S.OUTPUTS[j].script_params,
      Π
    )
    P.outputs[j].scriptPubKey == expected

  Case OP_RETURN:
    payload = resolveHexData(S.OUTPUTS[j].hex_payload, Π)
    expected = buildOpReturnScript(payload)
    P.outputs[j].scriptPubKey == expected

  → failure: BTSL_ERR_02 (BINDING_FAILURE — extended to outputs)

O-2 (amount):
  Case ADDRESS, CHANGE, or SCRIPT:
    P.outputs[j].value == expectedAmount(S.OUTPUTS[j], calc_vars, consts)
  Case OP_RETURN:
    P.outputs[j].value == 0
  → failure: BTSL_ERR_06 (ASSERT_FAILURE)

═══════════════════════════════════════════════════════════════════════
 ALGEBRAIC PREDICATES
═══════════════════════════════════════════════════════════════════════

A-1 (calc replay):
  The calc block MUST execute without runtime error using:
  - Parameters from Π (same as Maker)
  - UTXO amounts from certified chain values (I-3), NOT from PSBT
  - vSize from canonical weight model (spec §3.5), NOT from wallet estimation
  Any arithmetic exception (div/0, overflow, negative SAT) →
  → failure: BTSL_ERR_08 (ARITHMETIC_ERROR)

A-2 (ASSERT):
  All ASSERT clauses MUST be evaluated in numerical index order.
  Partial execution is prohibited. Any false condition →
  → failure: BTSL_ERR_06 (ASSERT_FAILURE)
  Non-sequential indices (gaps) → emit BTSL_WARN_02

A-3 (implicit balance):
  If a calc variable named 'fees' exists:
    SUM(certified_input_amounts) == SUM(P.output_amounts) + fees
    → failure: BTSL_ERR_06 (ASSERT_FAILURE)
  If 'fees' is absent from calc:
    → emit BTSL_WARN_06 (balance check skipped)

A-4 (dust):
  For every output j of type ADDRESS, CHANGE, or SCRIPT:
    P.outputs[j].value >= DUST_LIMIT
  (OP_RETURN outputs are exempt — their amount is 0 by O-2)
  → failure: BTSL_ERR_07 (DUST_OUTPUT)

A-5 (weight warning):
  tx_weight computed from canonical weight model (spec §3.5).
  If tx_weight > 400,000 wu:
    → emit BTSL_WARN_07

═══════════════════════════════════════════════════════════════════════
 ERROR CODE TAXONOMY (complete mapping)
═══════════════════════════════════════════════════════════════════════

 Phase        Code     Name                    Predicates
 ──────────── ──────── ─────────────────────── ────────────────────────
 Parse        ERR_00   SYNTAX_ERROR            .bts file malformed
 Shape        ERR_13   SCHEMA_MISMATCH         S-1, S-2            ← NEW
 Structural   ERR_01   TYPE_MISMATCH           I-1, I-4
 Structural   ERR_02   BINDING_FAILURE         I-1 (anchored), O-1
 Structural   ERR_12   OUTPOINT_MISMATCH       I-2 Case A; I-2 Case C (confirmed parent mismatch)
 Dependency   ERR_05   UNRESOLVED_DEPENDENCY   I-2 Case C (parent unbroadcast / unavailable)
 Zero-trust   ERR_11   PREVOUT_VALUE_MISMATCH  I-3                 ← NEW
 Algebraic    ERR_06   ASSERT_FAILURE          O-2, A-2, A-3
 Algebraic    ERR_07   DUST_OUTPUT             A-4
 Algebraic    ERR_08   ARITHMETIC_ERROR        A-1

 ERR_11  PREVOUT_VALUE_MISMATCH — The PSBT-declared input amount
   (witnessUtxo.value or nonWitnessUtxo extracted value) does not match
   the independently fetched on-chain value for that txid:vout.
   Zero-trust validation failed (§9.3 step 2; predicate I-3).

 ERR_12  OUTPOINT_MISMATCH — The txid:vout of a PSBT input does not match
   the outpoint declared in the bound parameters (I-2 Case A), or does not match
   the confirmed parent workflow output when the parent is already on-chain (I-2 Case C, §9.4).

 ERR_13  SCHEMA_MISMATCH — The PSBT structure is incompatible with the schema:
   the number of inputs or outputs in the PSBT does not match the schema
   declaration (S-1 or S-2). No field-level verification is possible.
   This is a fast-fail condition; the Checker halts immediately.

═══════════════════════════════════════════════════════════════════════
 SUMMARY TABLE
═══════════════════════════════════════════════════════════════════════

 ID    PHASE         PSBT FIELD VERIFIED            ERR          STATUS
 ───── ────────────  ─────────────────────────────  ──────────── ──────────
 S-1   shape         input count                    ERR_13       ERR updated
 S-2   shape         output count                   ERR_13       ERR updated
 I-1   structural    input scriptPubKey type        ERR_01/02    in spec
 I-2   structural    input txid:vout vs params      ERR_12       NEW
 I-3   zero-trust    input amount vs chain          ERR_11       ERR updated
 I-4   structural    input nSequence vs schema      ERR_01       NEW
 O-1   structural    output scriptPubKey (all)      ERR_02       NEW
 O-2   algebraic     output amount vs calc          ERR_06       in spec
 A-1   algebraic     calc deterministic replay      ERR_08       in spec
 A-2   algebraic     ASSERT full evaluation         ERR_06       in spec
 A-3   algebraic     implicit balance invariant     ERR_06       in spec
 A-4   algebraic     dust threshold                 ERR_07       in spec
 A-5   warning       weight > 400k wu               WARN_07      in spec

 TOTAL: 13 predicates
   3 NEW predicates:       I-2, I-4, O-1
   3 NEW error codes:      ERR_11, ERR_12, ERR_13
   2 ERROR CODE UPDATES:   S-1/S-2 (ERR_00 → ERR_13), I-3 (ERR_01 → ERR_11)

═══════════════════════════════════════════════════════════════════════
 COMPLETENESS ARGUMENT
═══════════════════════════════════════════════════════════════════════

The Maker (Step 1.5) writes the following fields into the PSBT.
Each field MUST have a corresponding Checker predicate:

 Maker writes (per input)        Checked by
 ──────────────────────────────  ──────────
 txid                            I-2
 vout                            I-2
 sequence                        I-4
 witnessUtxo.script              I-1
 witnessUtxo.amount              I-3
 nonWitnessUtxo (P2PKH)          I-3 (amount extracted from raw tx)
 witnessScript (P2WSH)           I-1 (hash-committed in scriptPubKey)
 tapLeafScript (P2TR script)     I-1 (committed in tweaked output key)
 tapInternalKey (P2TR)           I-1 (committed in tweaked output key)

 Maker writes (per output)       Checked by
 ──────────────────────────────  ──────────
 scriptPubKey                    O-1
 value                           O-2

 No PSBT field written by the Maker is left unchecked.

═══════════════════════════════════════════════════════════════════════
 BINDING PERSISTENCE — three levels (aligned with plan §9.1)
═══════════════════════════════════════════════════════════════════════

Level 1 — NORMATIVE (semantic requirement)

  When the Maker exports a PSBT to an external Checker, it MUST persist
  the results of From(@PUBKEY) AS alias so that the Checker can apply
  I-2 Case A (strict outpoint verification).

  Minimum data per alias (semantic types — no file encoding prescribed):
    alias.txid    — string, 64 hex characters, lowercase
    alias.vout    — non-negative integer
    alias.amount  — non-negative integer (sats)
    alias.address — string, valid Bitcoin address for the network

  This is the verifiable bar: a Checker that receives effective params
  MUST apply I-2 Case A. A Checker that receives only brut params
  MUST apply I-2 Case B (ownership-only fallback).

Level 2 — RECOMMENDED (cross-vendor .params interoperability)

  For implementations exchanging a .params file between parties
  (e.g. TypeScript Maker ↔ Rust Checker on a hardware wallet):

  RECOMMENDED convention: dot-notation extension of the existing
  key=value format (one entry per line, UTF-8, # for comments):
    {alias}.txid=<64 hex lowercase>
    {alias}.vout=<integer>
    {alias}.amount=<integer>
    {alias}.address=<address string>

  Implementations claiming cross-vendor Truth Triplet interoperability
  SHOULD emit and accept this convention when the transport is a
  .params file.

Level 3 — IMPLEMENTATION-DEFINED (same-process transport)

  When Maker and Checker run in the same process (e.g. playground,
  testing), any internal format (in-memory, IPC) MAY be used, provided
  the Level 1 semantic requirement is satisfied at verification time.

Links:
  - I-2 Case B: applies when Level 1 has NOT been satisfied (brut params
    only). Ownership verification replaces strict outpoint check.
  - DEPENDS_ON workflows (§9.4): Level 1 (or equivalent reproducible
    binding) is REQUIRED for reliable multi-schema chaining.
  - §4.5 anchor: after From() selection, a Maker exporting to an external
    Checker MUST satisfy Level 1 semantics before export.

═══════════════════════════════════════════════════════════════════════
 VISUAL SUMMARY
═══════════════════════════════════════════════════════════════════════

                    STRUCTURAL                    ALGEBRAIC
                (PSBT matches schema          (numbers are correct)
                 structure)
                      │                              │
    Shape:    S-1 input count                        │
    [ERR_13]  S-2 output count                       │
              (fast-fail — halt if fails)            │
                      │                              │
    Inputs:   I-1 ownership/type              I-3 zero-trust amounts
    [ERR_01]  I-2 txid:vout binding           [ERR_11]
    [ERR_12]  I-4 sequence
    [ERR_01]
                      │                              │
    Calc:           —                          A-1 deterministic replay
                                               [ERR_08]
                      │                              │
    Outputs:  O-1 destinations                O-2 amounts (from calc)
    [ERR_02]  (addresses, scripts,            [ERR_06]
               OP_RETURN payloads)            A-3 balance invariant
                                              A-4 dust
                      │                              │
    ASSERT:         —                          A-2 business rules
                                               A-5 weight warning

┌──────────────────────────────────────────────────────────────────┐
│                     TRUTH TRIPLET (§9.1)                          │
│  PSBT (binary)  +  .bts (schema)  +  .params (bruts or effectifs)│
│                                                                   │
│  .params bruts:    → I-2 Case B (ownership check only)           │
│  .params effectifs → I-2 Case A (strict outpoint check)          │
│  (Level 1 persisted)                                              │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│               CHECKER VERIFICATION                                │
│                                                                   │
│  Phase 0 (parse):   ERR_00 if .bts unparseable                   │
│  Phase 1 (shape):   S-1, S-2 → ERR_13 (fast-fail)               │
│  Phase 2 (fields):  I-1..I-4, O-1..O-2 → ERR_01/02/11/12        │
│  Phase 3 (algebra): A-1..A-5 → ERR_06/07/08/WARN_07             │
│                                                                   │
│  Implementation is FREE:                                          │
│  • Evaluate predicates independently       (predicate engine)     │
│  • Reconstruct expected PSBT + deep compare (Phantom Maker)       │
│  • Formal static verification              (future)               │
│                                                                   │
│  The standard defines PREDICATES, not algorithms.                 │
└──────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════
 SPEC PATCH GUIDE (integrated in spec — retained for audit)
═══════════════════════════════════════════════════════════════════════

The following items have been applied to `spec/btsl-spec-v1.0.md` (§5.3, §4.2,
§4.5.7, §7.5, §8, §9.1.1, §9.3, §9.3.1). This list remains as a change log
against the predicate document.

Changes integrated:

  §5.3 error table:
    ADD ERR_11 PREVOUT_VALUE_MISMATCH   (I-3, zero-trust step)
    ADD ERR_12 OUTPOINT_MISMATCH        (I-2 Case A; I-2 Case C when parent confirmed)
    ADD ERR_13 SCHEMA_MISMATCH          (S-1/S-2, shape fast-fail)
    UPDATE ERR_02 cause: extend to cover output scriptPubKey (O-1)
    NOTE: ERR_01 cause should mention I-4 (sequence) explicitly

  §9.3 step 2 (Checker pipeline):
    REPLACE ERR_01 for amount mismatch → ERR_11 PREVOUT_VALUE_MISMATCH
    ERR_06 also for O-2 (output amount vs calc) per §9.3.1

  §9.3.1 (new sub-section after §9.3):
    ADD normative predicate list S-1..A-5 with error code references
    ADD implementation freedom paragraph
    ADD phase ordering (shape → structural → algebraic)

  §9.1 Truth Triplet:
    ADD Binding Persistence three-level structure (Levels 1, 2, 3)
    KEEP PSBT + .bts + .params as the Truth Triplet definition

  §4.5 From() resolver:
    ADD one sentence: Maker exporting to external Checker MUST satisfy
    §9.1 Level 1 binding persistence semantics before export.

  §7 test vectors:
    ADD LG-12: ERR_11 — PSBT input value ≠ chain value
    ADD LG-13: ERR_12 — PSBT input txid:vout ≠ params UTXO
    ADD LG-14: ERR_01 — PSBT nSequence ≠ schema sequence
    ADD LG-15: ERR_02 — PSBT output scriptPubKey ≠ schema
    ADD LG-16: ERR_13 — PSBT input count ≠ schema INPUTS count

  §8 implementation checklist:
    UPDATE ERR range to ERR_00..ERR_13
    ADD Checker predicates §9.3.1
    ADD Binding persistence Level 1 (MUST) + Level 2 (SHOULD)
