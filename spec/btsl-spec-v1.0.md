# Bitcoin Transaction Schema Language (BTSL) — Specification v1.0

**Status:** Reference Specification [DRAFT]

**Date:** March 2026

**Author:** Thomas Suau

**Scope:** PSBT Construction, Audit, and Workflow (BIP174/BIP370)

---

> This document represents the state of the original author's work, who
> is no longer available to maintain it. It is published as-is in the
> hope that it can be continued by the community.
> Sections marked `[OPEN]` explicitly identify unresolved points.
> Future maintainers are invited to open discussions on those matters.

---

## 1. Abstract

**BTSL** is a declarative language for the construction and auditing of Bitcoin transactions
via PSBT (BIP174/BIP370). It is not an imperative construction tool, but a protocol for the
**formalization of economic invariants**: validation logic (fees, output structure, business
rules) is extracted from wallet application code and isolated within an independently
verifiable schema.

This separation between **untrusted construction** (coordinator) and **trusted verification**
(signer) ensures that any signature is applied with full awareness of the business rules,
without blind trust in the software that generated the PSBT.

### 1.1. Design Rationale: BTSL as an "Implementation Guide"

> BTSL draws inspiration from the rigor of business-to-business exchange standards
> (e.g., EDIFACT), where message precision is guaranteed by strict control structures.
> Whereas those standards are passive (data carriers), BTSL is active: it acts as a
> self-validating *Implementation Guide*, transforming an opaque binary message (PSBT)
> into a business contract whose invariants are verifiable by both sender and receiver
> prior to any broadcast. This is what BTSL terms the **Policy-as-Code** layer.

### 1.2. Note to Implementers: BTSL and Standardization

**BTSL** was designed to address the fragmentation of PSBT workflow construction methods.
To secure its long-term viability within the Bitcoin ecosystem (notably for adoption by
reference libraries such as `rust-bitcoin` or `libpsbt`), this specification adheres to
the following principles:

1. **Namespace Interoperability:** BTSL does not modify the existing PSBT format
   (BIP174/BIP370), but augments it via proprietary fields (`PSBT_GLOBAL_UNKNOWN`).
   This guarantees that any BTSL transaction remains valid and parsable by any
   BIP370-compatible wallet, even in the absence of a BTSL validator.

2. **Security via Invariants (Enforcer):** Unlike imperative programming languages,
   BTSL explicitly separates **calculation logic** (`calc`) from **integrity validation**
   (`ASSERT`). This separation provides a fundamental guarantee: a BTSL validation engine
   can be implemented in a deterministic and isolated manner, drastically reducing the
   attack surface when signing critical transactions (Multisig, Vaults).

3. **Transparency Regarding Protocol Risks:** BTSL fully acknowledges the current
   limitations of the Bitcoin protocol (notably `txid` malleability in the absence of
   BIP118/BIP119). Rather than proposing "magic" mitigations, BTSL documents these risks
   as structural, allowing developers to design systems fully aware of their network
   environment constraints.

4. **Implementation Agnosticism:** BTSL defines the **"What"** (grammar) and the
   **"How"** (calculation semantics), but leaves the **"How to code it"** to each
   library's technical choices. A BTSL compiler in Rust or C++ is considered as
   compliant as one in JavaScript, provided it strictly adheres to the `BTSL_ERR_XX`
   error code table and the `sats` normalization logic.

> **Recommendation to future contributors:** The "Policy-as-Code" approach described
> herein represents a mature starting point. The natural next step is the integration of
> a Merkle inclusion proof mechanism (SPV/Full-node) for complete `Zero-Trust` validation
> in isolated (Air-gapped) environments, without relying on an active network connection.

---

## 2. Formal Grammar (EBNF)

The grammar uses explicit indentation management (`INDENT` / `DEDENT`) to define block
scope, ensuring deterministic parsing.

> **Normative Indentation Rule:** BTSL files MUST use either **spaces only** or **tabs
> only** throughout a given file. Mixed indentation (tabs and spaces in the same file)
> MUST be rejected by the lexer with `BTSL_ERR_00`.

```ebnf
(* ================================================================ *)
(* TERMINALS                                                         *)
(* ================================================================ *)

(* NL: line terminator. Implementations MUST accept both LF (0x0A)  *)
(* and CRLF (0x0D 0x0A). CR alone (0x0D) is NOT valid.              *)
NL                  ::= "\n" | "\r\n"

(* COMMENT: a line comment. Spans from the delimiter to end-of-line. *)
(* The semicolon (;) is the BTSL comment character.                  *)
COMMENT             ::= ";", { any_char_except_NL }, NL

(* INDENT / DEDENT: synthetic tokens emitted by the lexer to signal  *)
(* an increase or decrease in indentation level. The unit is         *)
(* implementation-defined but MUST be consistent within a file.      *)
INDENT              ::= (* increase in indentation level *)
DEDENT              ::= (* decrease in indentation level *)

(* Normative Colon Rule:                                             *)
(* The lexer MUST emit SECTION_OPEN when ":" is immediately          *)
(* followed by NL then INDENT (block opener).                        *)
(* The lexer MUST emit COLON in all other positions.                 *)
(* Exception: a ":" immediately following an INTEGER token           *)
(* is ALWAYS emitted as COLON — regardless of what follows.          *)
(* This applies uniformly to input indices, output indices,         *)
(* and assert indices. A lexer MUST NOT emit SECTION_OPEN            *)
(* in this position even if NL + INDENT follows.                    *)
(* A ":" at end-of-line NOT followed by INDENT → BTSL_ERR_00.       *)
(* This rule makes workflow_ref, input/output indices, and           *)
(* inline field assignments unambiguous in all contexts.             *)
SECTION_OPEN        ::= ":", NL, INDENT
COLON               ::= ":"

(* Identifier taxonomy — Lexer Priority: PASCAL_CASE_ID             *)
(*                                      > snake_case_id              *)
(*                                      > IDENTIFIER                 *)
IDENTIFIER          ::= [a-zA-Z_][a-zA-Z0-9_]*
PASCAL_CASE_ID      ::= [A-Z][a-zA-Z0-9]*
snake_case_id       ::= [a-z][a-z0-9_]*
INTEGER             ::= [0-9]+
STRING              ::= '"', { any_char_except_'"' }, '"'
HEX_DATA            ::= "0x", [0-9a-fA-F]+
BOOLEAN             ::= "true" | "false"

(* ================================================================ *)
(* RESERVED KEYWORDS                                                 *)
(* The following identifiers are reserved and MUST NOT be used as   *)
(* user-defined names (IDENTIFIER, PASCAL_CASE_ID, snake_case_id):  *)
(*   VERSION CONST PARAMS OPTIONS REQUIRED SCRIPT_DEFS              *)
(*   PSBT_SCHEMA INPUTS OUTPUTS FOREACH IMPORT UNLOCK USING         *)
(*   CHANGE NATIVE ASSERT calc DEPENDS_ON AS                        *)
(*   OP_RETURN OP_CSV OP_CHECKSIG OP_CHECKMULTISIG OP_DROP          *)
(*   P2TR P2WSH P2SH P2WPKH P2PKH P2TR_KEY                         *)
(*   UTXO ADDRESS FEERATE HEX_DATA SATOSHI BOOLEAN                  *)
(*   Pubkey From                                                     *)
(*   true false                                                      *)
(* ================================================================ *)

(* ================================================================ *)
(* 1. TOP LEVEL                                                      *)
(* ================================================================ *)

btsl_file           ::= { NL | COMMENT }*,
                        version_header,
                        [ const_section ],
                        [ params_section ],
                        { import_declaration },
                        { script_defs_section },
                        { psbt_schema_section }+

version_header      ::= "VERSION", COLON, INTEGER, NL

(* ================================================================ *)
(* 2. DEFINITION SECTIONS                                            *)
(* ================================================================ *)

(* CONST scoping rules:                                              *)
(* A CONST declared at top-level (btsl_file) is GLOBAL: visible in  *)
(* all PSBT_SCHEMA sections within the file.                         *)
(* A CONST declared inside a PSBT_SCHEMA is LOCAL: visible only in  *)
(* that schema (OUTPUTS, calc, ASSERT).                              *)
(* LOCAL takes precedence over GLOBAL for identical names           *)
(* (shadowing). Shadowing MUST emit BTSL_WARN_09.                   *)
(* Redefinition within the SAME scope is BTSL_ERR_00.               *)
const_section       ::= "CONST", SECTION_OPEN, { const_assignment, NL }+, DEDENT
const_assignment    ::= IDENTIFIER, "=", value

params_section      ::= "PARAMS", SECTION_OPEN, { param_declaration, NL }+, DEDENT
param_declaration   ::= "@", PASCAL_CASE_ID,
                        [ COLON, ("UTXO" | "ADDRESS" | "FEERATE" | "HEX_DATA" | "SATOSHI" | "Pubkey") ]

options_section     ::= "OPTIONS", SECTION_OPEN,
                            { option_assignment, NL }*,
                            [ dependency_declaration, NL ],
                        DEDENT
option_assignment   ::= IDENTIFIER, "=", value
dependency_declaration ::= "DEPENDS_ON", PASCAL_CASE_ID

(* ================================================================ *)
(* 3. SCRIPT_DEFS                                                    *)
(* ================================================================ *)

script_defs_section ::= "SCRIPT_DEFS", SECTION_OPEN, { script_definition, NL }+, DEDENT
script_definition   ::= PASCAL_CASE_ID, script_type, SECTION_OPEN,
                            (p2tr_body | p2wsh_body | p2sh_body), DEDENT
script_type         ::= "P2TR" | "P2WSH" | "P2SH"

p2tr_body           ::= "internal_key", COLON, internal_key_ref, NL,
                        "paths", SECTION_OPEN,
                        { path_definition, NL }+, DEDENT

(* internal_key_ref: either a user-defined identifier OR the        *)
(* reserved keyword NUMS_KEY (see §3.7 — Taproot Security Model).   *)
internal_key_ref    ::= "NUMS_KEY" | IDENTIFIER

path_definition     ::= (PASCAL_CASE_ID | snake_case_id), "SCRIPT", SECTION_OPEN,
                            "leaf_version", COLON, INTEGER, NL,
                            "witness", SECTION_OPEN, { witness_placeholder, NL }+, DEDENT,
                            asm_block,
                        DEDENT

p2wsh_body          ::= asm_block
p2sh_body           ::= asm_block

(* inline asm (space-separated) or multiline (indented) *)
asm_block           ::= asm_multiline | asm_inline
asm_multiline       ::= "asm", SECTION_OPEN, { asm_element, NL }+, DEDENT
asm_inline          ::= "asm", COLON, " ", asm_element, { " ", asm_element }+, NL

(* Note on asm_inline: elements are separated by exactly one or     *)
(* more ASCII space characters (0x20). The lexer MUST NOT emit a    *)
(* SPACE token; spaces serve solely to delimit terminals in this    *)
(* specific context.                                                 *)

asm_element         ::= "<pubkey(" IDENTIFIER ")>"
                      | "<num_asm(" IDENTIFIER ")>"
                      | IDENTIFIER
                      | value

witness_placeholder ::= "<sig(" IDENTIFIER ")>"
                      | "<data(" IDENTIFIER ")>"
                      | "<num(" IDENTIFIER ")>"
                      | "<empty>"

(* <empty> pushes an empty byte array (0 bytes) onto the witness     *)
(* stack. Required as OP_CHECKMULTISIG dummy element (BIP147).       *)
(* Weight: 1 wu (1-byte varint encoding length 0).                   *)

(* ================================================================ *)
(* 4. PSBT SCHEMA                                                    *)
(* ================================================================ *)

psbt_schema_section ::= "PSBT_SCHEMA", PASCAL_CASE_ID, SECTION_OPEN,
                            [ const_section ],
                            [ params_section ],
                            [ options_section ],
                            inputs_section,
                            outputs_section,
                            [ calc_section ],
                            [ assert_section ],
                        DEDENT

(* NOTE: The REQUIRED section is syntactically recognized but        *)
(* reserved in v1.0. See §3.2.                                       *)

(* ================================================================ *)
(* 5. INPUTS & OUTPUTS                                               *)
(* ================================================================ *)

inputs_section      ::= "INPUTS", SECTION_OPEN, { input_line, NL }+, DEDENT
input_line          ::= loop_block | single_input

(* FOREACH: reserved syntax — not part of the normative evaluable   *)
(* core of v1.0. Presence MUST emit BTSL_WARN_01.                   *)
(* MUST NOT influence evaluation.                                    *)
loop_block          ::= "FOREACH", PASCAL_CASE_ID, "AS", PASCAL_CASE_ID, SECTION_OPEN,
                        single_input, DEDENT

(* IMPORT: reserved syntax — not part of the normative evaluable    *)
(* core of v1.0. Presence MUST emit BTSL_WARN_01.                   *)
(* MUST NOT influence evaluation.                                    *)
import_declaration  ::= "IMPORT", STRING, NL

single_input        ::= INTEGER, COLON, [ native_input_type ], input_source
native_input_type   ::= "NATIVE", ("P2PKH" | "P2WPKH" | "P2TR_KEY")

(* input_source handles both complex scripts and native standards *)
input_source        ::= simple_input_block | unlock_block

simple_input_block  ::= NL, INDENT, "utxo", COLON, (reference | utxo_resolver), NL, DEDENT

(* utxo_resolver: auto-selects a UTXO from a Pubkey @PARAM.          *)
(* The AS alias is MANDATORY — omitting it is BTSL_ERR_00.            *)
(* It exposes alias.amount in calc and alias.address in OUTPUTS.      *)
(* Selection strategy: largest confirmed UTXO (largest-first).        *)
(* No confirmed UTXO available → BTSL_ERR_09.                         *)
(* Type inference without native_input_type → BTSL_WARN_08.           *)
(* Only valid in simple_input_block. Usage in unlock_block, calc,     *)
(* or ASSERT → BTSL_ERR_00.                                           *)
utxo_resolver       ::= "From", "(", compile_ref, ")", "AS", snake_case_id

unlock_block        ::= "UNLOCK", PASCAL_CASE_ID,
                        [ "USING", (PASCAL_CASE_ID | snake_case_id) ], SECTION_OPEN,
                            "utxo", COLON, reference, NL,
                            [ "sequence", COLON, INTEGER, NL ],
                            [ script_params_block ],
                            [ witness_data_block ],
                        DEDENT

script_params_block ::= "script_params", SECTION_OPEN, { param_assignment, NL }+, DEDENT

(* Normative Witness Binding Rule:                                   *)
(* Applies ONLY when the referenced script path declares a           *)
(* "witness:" block (P2TR script paths via path_definition).        *)
(* P2WSH and P2SH bodies (p2wsh_body, p2sh_body) do not declare     *)
(* witness placeholders; witness_data entries for those script types *)
(* are not subject to nominal binding validation.                    *)
(* The identifiers in witness_data MUST correspond NOMINALLY to      *)
(* the placeholder names declared in the "witness:" block of the     *)
(* referenced script path.                                           *)
(* Matching is case-sensitive and exact.                             *)
(* An identifier in witness_data with no matching placeholder        *)
(* → BTSL_ERR_10.                                                    *)
(* A placeholder declared in "witness:" with no corresponding        *)
(* witness_data entry → BTSL_ERR_10.                                 *)
(* Order of witness_assignment entries in witness_data MUST match    *)
(* the declaration order of witness_placeholder in "witness:".       *)
(* Order mismatch with correct names → BTSL_ERR_10.                 *)
witness_data_block  ::= "witness_data", SECTION_OPEN, { witness_assignment, NL }+, DEDENT
param_assignment    ::= IDENTIFIER, "=", (value | compile_ref)
witness_assignment  ::= IDENTIFIER, "=", (sign_with_directive | "<empty>")
sign_with_directive ::= "<SIGN_WITH(", reference, ")>"

outputs_section     ::= "OUTPUTS", SECTION_OPEN, { output_line, NL }+, DEDENT
output_line         ::= INTEGER, COLON, output_type

(* Normative Positional Rule for output_type:                        *)
(* The parser reads a single line left-to-right:                     *)
(*   position 1 → address_ref (exactly one syntactic unit)           *)
(*   position 2 → amount value (INTEGER | snake_case_id | IDENTIFIER)*)
(*   position 3 → optional unit suffix — absent means sats          *)
(* A bare snake_case_id at position 1 is ONLY valid as address_ref   *)
(* if immediately followed by "." (i.e., it is an alias_ref).        *)
(* A bare snake_case_id at position 1 NOT followed by "."            *)
(* → BTSL_ERR_00.                                                     *)
(* "btc" values are normalized ×100,000,000 at parse time.           *)
(* The runtime manipulates SAT integers exclusively.                  *)
output_type         ::= (address_ref, amount)
                      | ("OP_RETURN", (HEX_DATA | compile_ref))
                      | ("CHANGE", address_ref, amount)
                      | ("SCRIPT", PASCAL_CASE_ID, amount,
                            [ NL, INDENT, script_params_block, DEDENT ])

amount              ::= (INTEGER, [ ("sats" | "btc") ])
                      | ((snake_case_id | IDENTIFIER), [ ("sats" | "btc") ])

(* unit absent → sats. Normative default, enforced at parse time.    *)

(* address_ref: exactly one syntactic unit. snake_case_id only valid *)
(* as part of alias_ref (requires "." suffix). Bare snake_case_id    *)
(* is NOT a valid address_ref.                                        *)
(* Lexer priority PASCAL_CASE_ID > snake_case_id > IDENTIFIER: a     *)
(* token such as `foo` is always snake_case_id, never IDENTIFIER.    *)
(* Thus IDENTIFIER in address_ref covers only forms lexed as         *)
(* IDENTIFIER (e.g. identifiers starting with "_").                  *)
address_ref         ::= STRING
                      | compile_ref
                      | alias_ref
                      | PASCAL_CASE_ID
                      | IDENTIFIER

(* ================================================================ *)
(* 6. LOGIC AND EXPRESSIONS                                          *)
(* ================================================================ *)

calc_section        ::= "calc", SECTION_OPEN, { calc_assignment, NL }+, DEDENT
calc_assignment     ::= snake_case_id, "=", expression

assert_section      ::= "ASSERT", SECTION_OPEN, { assert_line, NL }+, DEDENT
assert_line         ::= INTEGER, COLON, condition
condition           ::= expression, (">" | "<" | "==" | ">=" | "<=" | "!="), expression

expression          ::= additive

additive            ::= multiplicative, { ("+" | "-"), multiplicative }

multiplicative      ::= primary, { ("*" | "/"), primary }

(* Standard arithmetic precedence: "*" and "/" bind tighter than    *)
(* "+" and "-". Parentheses override precedence.                    *)
(* Division truncates toward zero (floor for positive operands).    *)
(* See §3.6.C for arithmetic error rules (BTSL_ERR_08).             *)

(* Normative Alias Priority Rule:                                    *)
(* alias_ref MUST be attempted before value in primary.             *)
(* A snake_case_id immediately followed by "." is ALWAYS            *)
(* resolved as alias_ref — never as value.                          *)
(* A snake_case_id NOT followed by "." is resolved as value.        *)
(* Lookahead of exactly one token ("." or not) is sufficient.       *)
(* No ambiguity remains after this single-token lookahead.          *)
primary             ::= alias_ref
                      | function_call
                      | compile_ref
                      | onchain_ref
                      | workflow_ref
                      | value
                      | "(", expression, ")"

(* alias_ref: references a property of a From() resolver alias.      *)
(* alias.amount is valid in calc (resolves to SAT).                   *)
(* alias.address is valid as address_ref in OUTPUTS.                  *)
alias_ref           ::= snake_case_id, ".", ("amount" | "address")

function_call       ::= ("vSize" | "SUM" | "COUNT"), "(", function_args, ")"
function_args       ::= context_target | compile_ref | IDENTIFIER
context_target      ::= "INPUTS"
                      | "CURRENT_PSBT"
                      | (PASCAL_CASE_ID, ".", IDENTIFIER)

(* ================================================================ *)
(* 7. REFERENCES                                                     *)
(* ================================================================ *)

reference           ::= compile_ref | onchain_ref | workflow_ref

(* compile_ref: resolved at bind time from the .params file.        *)
compile_ref         ::= "@", PASCAL_CASE_ID,
                        [ ".", ("amount" | "txid" | "vout" | "address") ]

(* onchain_ref: REF() forces an on-chain query to the indexer.      *)
(* It MUST be used when the caller requires the live blockchain      *)
(* value rather than the value declared in the PSBT or params.      *)
(* Accepted inner targets: compile_ref OR workflow_ref.             *)
(* Using REF() on a compile_ref fetches the live UTXO value         *)
(*   for that param (e.g., current amount of @BOB_UTXO).            *)
(* Using REF() on a workflow_ref fetches the confirmed output value *)
(*   of a previously broadcast schema transaction.                  *)
onchain_ref         ::= "REF", "(",
                            (compile_ref | workflow_ref),
                        ")"

(* workflow_ref: references an output of a previously declared      *)
(* PSBT_SCHEMA by name and index.                                    *)
workflow_ref        ::= PASCAL_CASE_ID, COLON, INTEGER, ".",
                        ("amount" | workflow_outpoint)
workflow_outpoint   ::= "txid", COLON, INTEGER

value               ::= INTEGER | STRING | HEX_DATA | BOOLEAN
                      | snake_case_id | IDENTIFIER
```

---

## 3. Normative Core v1.0

This section defines the mandatory implementation rules for any compliant BTSL compiler
or engine. It governs the interpretation of all subsequent sections.

### 3.1. Mandatory and Optional Sections

| Section        | Status      | Note                                                                          |
| :------------- | :---------- | :---------------------------------------------------------------------------- |
| `VERSION`      | REQUIRED    | Absence → `BTSL_ERR_00`                                                       |
| `INPUTS`       | REQUIRED    | Absence → `BTSL_ERR_00`                                                       |
| `OUTPUTS`      | REQUIRED    | Absence → `BTSL_ERR_00`                                                       |
| `PARAMS`       | CONDITIONAL | REQUIRED if any `@PARAM` reference appears in the schema. Absence with references → `BTSL_ERR_04b` |
| `CONST` (global) | OPTIONAL    | Visible in all schemas. Shadowed by local `CONST`.                          |
| `CONST` (local)  | OPTIONAL    | Visible in its `PSBT_SCHEMA` only. Shadows global `CONST`.                    |
| `SCRIPT_DEFS`  | OPTIONAL    | —                                                                             |
| `OPTIONS`      | OPTIONAL    | —                                                                             |
| `calc`         | OPTIONAL    | —                                                                             |
| `ASSERT`       | OPTIONAL    | If present, **all** assertions MUST be evaluated. Partial execution is strictly prohibited. |

> Each section MUST appear **at most once** per `PSBT_SCHEMA`. A duplicate section raises `BTSL_ERR_00`.
>
> **Note:** A top-level `CONST` block applies to the whole file; a `CONST` block inside a `PSBT_SCHEMA` is local to that schema. At most one top-level `CONST` block per file and at most one `CONST` block per `PSBT_SCHEMA`. Duplicate `CONST` blocks at the same level → `BTSL_ERR_00`.

---

### 3.2. Reserved Sections

The following sections are syntactically recognized but **not evaluated** in v1.0:

| Section    | Status   | Behavior                                                         |
| :--------- | :------- | :--------------------------------------------------------------- |
| `FOREACH`  | RESERVED | Presence tolerated → `BTSL_WARN_01`. MUST NOT influence evaluation. |
| `IMPORT`   | RESERVED | Presence tolerated → `BTSL_WARN_01`. MUST NOT influence evaluation. |
| `REQUIRED` | RESERVED | Presence tolerated → `BTSL_WARN_01`. MUST NOT influence evaluation. Semantics deferred to v2.0. |

> Reserved sections MUST NOT produce any effect on the compilation result, the `calc`
> variables, or the `ASSERT` statements. A compiler MUST NOT raise an error on their
> presence alone.

---

### 3.3. Extension Policy

A BTSL compiler encountering an **unknown** (non-reserved, non-specified) section MUST
apply the following rules:

1. **Unknown semantic sections** (liable to influence calculation or validation): MUST
   trigger `BTSL_ERR_00`.
2. **Unknown non-semantic sections** (metadata, documentation, display): MAY be ignored
   with the emission of `BTSL_WARN_01`.

> **Default rule:** Any unknown section is considered **semantic** unless explicitly
> declared otherwise in a subsequent version of the standard. When in doubt, a compliant
> compiler MUST reject.

---

### 3.4. Evaluation Order (Normative Pipeline)

The BTSL engine MUST execute the following steps in this strict order:

```
1. Parse          — Syntactic validation, VERSION check, INDENT/DEDENT normalization
2. Bind           — Resolution of @PARAMS from the .params file
3. compile_ref    — Resolution of static references (@PARAM.prop)
4. onchain_ref    — Resolution of REF() targets via on-chain indexer
5. calc           — Sequential evaluation in declaration order
6. ASSERT         — Execution in numerical order (0 to N)
7. Produce PSBT   — Serialization and Base64 export
```

> Any failed step **immediately halts the pipeline**. The subsequent step MUST NOT be
> executed. A partial result MUST NOT be exported as a valid PSBT.

---

### 3.5. Canonical Weight Model (`vSize`)

The BTSL compiler MUST calculate transaction weight **deterministically** via the
canonical model below, independently of the wallet's runtime state.

> **Design rationale:** All intermediate calculations are performed in **weight units (wu)**
> to avoid integer rounding accumulation. The `vsize` (in virtual bytes) is derived by a
> single `ceil()` operation at the end. This guarantees that the computed fee rate will
> never be invalidated upon signing (Worst-Case Canonical Weight).

#### 3.5.1. Normative Formula

```
tx_weight = BASE_TX_OVERHEAD
          + SEGWIT_OVERHEAD        (* conditional — see below *)
          + Σ input_weight(input_i)
          + Σ output_weight(output_j)

vsize = ceil(tx_weight / 4)        (* single rounding operation *)
```

#### 3.5.2. Transaction Overhead

| Constant             | Value  | Derivation                                                    |
| :------------------- | :----- | :------------------------------------------------------------ |
| `BASE_TX_OVERHEAD`   | 40 wu  | `version`(4B) + `vin_count` varint(1B) + `vout_count` varint(1B) + `locktime`(4B) = 10B × 4 |
| `SEGWIT_OVERHEAD`    | 2 wu   | segwit `marker`(1B) + `flag`(1B), weight factor = 1. **Present if and only if at least one input is a segwit type (P2WPKH, P2TR, P2WSH).** |

> A pure-legacy transaction (all `P2PKH` inputs) uses `BASE_TX_OVERHEAD = 40 wu` and
> `SEGWIT_OVERHEAD = 0`. Any transaction containing at least one segwit input MUST add
> `SEGWIT_OVERHEAD = 2 wu`.

#### 3.5.3. `input_weight` Table

All weights are expressed in **wu (weight units)**. Non-witness fields carry a weight
factor of 4 (BIP141). Witness fields carry a weight factor of 1.

> **Derivation for standard inputs:** The non-witness portion of any segwit input is
> `prevout`(36B) + `scriptSig_len` varint(1B) + `scriptSig`(0B) + `nSequence`(4B) = 41
> bytes. Its weight contribution is 41 × 4 = **164 wu**.

| Type           | Non-witness contrib. (wu) | Witness contrib. (wu)                            | Total (wu)        |
| :------------- | :------------------------ | :----------------------------------------------- | :---------------- |
| `P2PKH`        | 592 wu *(148B × 4)*       | 0                                                | **592 wu**        |
| `P2WPKH`       | 164 wu *(41B × 4)*        | 109 wu *(1B items_count + 1B sig_len + 73B sig + 1B pk_len + 33B pk)* | **273 wu** |
| `P2TR_KEY`     | 164 wu *(41B × 4)*        | 66 wu *(1B items_count + 1B sig_len + 64B Schnorr sig)* | **230 wu** |
| `P2WSH`        | 164 wu *(41B × 4)*        | `script_witness_weight` (sww)                    | **164 + sww wu**  |
| `P2TR_SCRIPT`  | 164 wu *(41B × 4)*        | `script_witness_weight` (sww) + `control_block_weight` (cbw) | **164 + sww + cbw wu** |

> **P2PKH derivation:** The scriptSig for a P2PKH input (WCC) is:
> `OP_DATA`(1B) + DER_sig(73B WCC) + `OP_DATA`(1B) + compressed_pubkey(33B) = 108B.
> Full input: prevout(36B) + scriptSig_len(1B) + scriptSig(108B) + nSequence(4B) = 149B. 
> Rounding to the standard value of **148B × 4 = 592 wu** is accepted 
> (conservative, widely used by Bitcoin Core).

#### 3.5.4. `output_weight` Table

Outputs contain no witness data. All bytes are multiplied by 4.

| Type          | Weight (wu)                                  | Derivation                               |
| :------------ | :------------------------------------------- | :--------------------------------------- |
| `P2WPKH`      | 124 wu                                       | (8 + 1 + 22)B × 4                        |
| `P2TR`        | 172 wu                                       | (8 + 1 + 34)B × 4                        |
| `P2WSH`       | 172 wu                                       | (8 + 1 + 34)B × 4                        |
| `P2PKH`       | 136 wu                                       | (8 + 1 + 25)B × 4                        |
| `OP_RETURN` | `(11 + len(payload)) × 4` wu | For len ≤ 75B.
|             | `(12 + len(payload)) × 4` wu | For 76 ≤ len ≤ 252B (OP_PUSHDATA1).
|             | `(13 + len(payload)) × 4` wu | For 253 ≤ len ≤ 65535B (OP_PUSHDATA2).
|             | No hard cap — standard tx weight limit (400K wu) applies.

> `OP_RETURN` payload constraint: Since Bitcoin Core v30 (October 2025), there is no
> fixed byte limit on `OP_RETURN` payloads at the default mempool policy level. The
> effective constraint is the **standard transaction weight limit of 400,000 wu**.
> However, nodes running Bitcoin Core v29 or earlier, or Bitcoin Knots, enforce a
> default limit of **80 bytes**. A payload exceeding 80 bytes MUST emit `BTSL_WARN_04`
> to signal potential rejection by a subset of the relaying network.
> The `-datacarriersize` configuration option remains available in Bitcoin Core v30
> for operators wishing to enforce a custom limit.
> For payloads of 76–80 bytes, the push opcode requires `OP_PUSHDATA1` (2 bytes instead
> of 1), yielding `(12 + len(payload)) × 4` wu.

#### 3.5.5. Auxiliary Weight Formulas

```
(* script_witness_weight: total witness bytes for a script-path spend.   *)
(* All values in wu (witness bytes, weight factor = 1).                  *)
script_witness_weight =
      1                                        (* varint: number of stack items *)
    + Σ (1 + size(witness_element_i))          (* varint(len) + element bytes   *)
    + 1 + len(serialized_script)               (* varint(script_len) + script   *)

(* Individual witness element weights:                                   *)
placeholder_weight:
    <sig(...)>    → 74 wu   (* varint(1) + DER sig WCC 73B — ECDSA       *)
                    65 wu   (* varint(1) + Schnorr sig 64B — P2TR        *)
    <data(...)>   → MUST be declared in the schema (mandatory if used)
    <num(...)>    → 9 wu    (* varint(1) + up to 8B CScriptNum WCC       *)
    <empty>       → 1 wu    (* varint(0) — empty byte array, no payload  *)

(* control_block_weight: witness weight of the Taproot control block.    *)
(* Includes the 1-byte varint prefix for the witness stack item.         *)
control_block_weight(depth) = 1 + 33 + (32 × depth)   (* = 34 + 32×depth wu *)
(*  1B  : varint for item length                                         *)
(*  1B  : leaf_version + parity bit                                      *)
(* 32B  : internal_key                                                   *)
(* 32×d : Merkle proof (d = depth in the Taproot script tree)           *)
```

---

### 3.6. Normative Type Table

#### A. Primitive Types

| Type     | Description              | Domain                                   |
| :------- | :----------------------- | :--------------------------------------- |
| `SAT`    | Unsigned integer, satoshi unit | ≥ 0. Negative intermediate result → `BTSL_ERR_08` |
| `INT`    | Generic unsigned integer | ≥ 0                                      |
| `BOOL`   | Boolean                  | `true` / `false`                         |
| `BYTES`  | Raw binary data          | Hex-encoded `0x...` (`HEX_DATA`)         |
| `STRING` | Character string         | UTF-8, delimited by `"`                  |

#### B. Bitcoin Types

| Type       | Description                      | Accessible Properties                                              |
| :--------- | :------------------------------- | :----------------------------------------------------------------- |
| `UTXO`     | Reference to an unspent output   | `.txid`, `.vout`, `.amount`, `.address`, `.script_type`            |
| `ADDRESS`  | Encoded Bitcoin address          | —                                                                  |
| `TXID`     | Transaction identifier (32 bytes)| —                                                                  |
| `FEERATE`  | Fee rate                         | In `sat/vByte`                                                     |
| `HEX_DATA` | Arbitrary binary data            | —                                                                  |
| `SATOSHI`  | Explicit alias of `SAT` for `@PARAMS` | ≥ 0                                                          |
| `Pubkey`   | Compressed secp256k1 public key (33 bytes) | —                                                    |

> The `.script_type` property of a `UTXO` MUST resolve to one of the following string
> literals: `"P2PKH"`, `"P2WPKH"`, `"P2TR"`, `"P2WSH"`, `"P2SH"`. Any other value
> raises `BTSL_ERR_04c`.

> A `Pubkey` value in the `.params` file MUST be a 33-byte compressed hex string
> (prefix `0x02` or `0x03`). Any other value raises `BTSL_ERR_04e`. Address derivation
> from `Pubkey` is performed by `From()` at bind time (§4.5).

> All listed properties are **normative** for the `UTXO` type. A compiler MUST resolve
> them if referenced. A missing or unresolvable property raises `BTSL_ERR_04b`.

#### C. Arithmetic Rules

| Operation              | Normative Rule                                                               |
| :--------------------- | :--------------------------------------------------------------------------- |
| Unit normalization     | Any `btc` value is normalized to `sats` (× 100,000,000) at **parse time**. The runtime manipulates `SAT` integers exclusively. |
| Implicit `sats`        | An `amount` field without an explicit unit suffix is treated as `sats`.      |
| Division               | Result truncated towards zero (floor division for positive operands).        |
| Negative `SAT` result  | `BTSL_ERR_08` (`ARITHMETIC_ERROR`)                                           |
| Integer overflow       | `BTSL_ERR_08` (`ARITHMETIC_ERROR`)                                           |
| Division by zero       | `BTSL_ERR_08` (`ARITHMETIC_ERROR`)                                           |
| Heterogeneous operands | Prohibited. Both operands of any arithmetic operation MUST be of the same normalized type (`SAT`). |

---

### 3.7. Taproot Security Model (`NUMS_KEY`)

This section defines the normative treatment of the `internal_key` field in `SCRIPT_DEFS`
of type `P2TR`.

#### 3.7.1. Key-Path vs. Script-Path Spending

A Taproot output commits to both an `internal_key` (enabling key-path spending) and a
Merkle root of scripts (enabling script-path spending). If the `internal_key` corresponds
to a known private key, that party can spend the output via the **key-path** — bypassing
all `SCRIPT_DEFS` conditions — provided they can produce a valid Schnorr signature.

**This is the intended behavior when key-path spending is desired.** However, for contracts
designed as **script-path only** (e.g., timelocked vaults, multisig schemes where the
key-path must be disabled), using a real key as `internal_key` constitutes a critical
security vulnerability: it silently grants an unconstrained spending path to the holder
of that private key.

#### 3.7.2. The `NUMS_KEY` Constant

To address this, BTSL defines a reserved identifier `NUMS_KEY` for use as `internal_key`:

```
NUMS_KEY = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

This value is the standard **Nothing-Up-My-Sleeve (NUMS) point** defined in BIP341
 (§Appendix A). It is a valid secp256k1 x-only public key for which no corresponding
private key is known, making key-path spending cryptographically infeasible.

#### 3.7.3. Normative Rules

1. **`internal_key: NUMS_KEY`** — Script-path only. The compiler MUST substitute the
   `NUMS_KEY` constant value when constructing the Taproot output. Emits no warning.

2. **`internal_key: <IDENTIFIER>`** — Key-path spending is **enabled**. The compiler
   MUST emit `BTSL_WARN_05` (`KEY_PATH_ENABLED`) to signal to the signer that an
   unrestricted spending path exists for the holder of the corresponding private key.
   The schema author bears full responsibility for this design choice.

> **Recommendation:** Use `NUMS_KEY` as `internal_key` in all script-path-only contracts
> (vaults, timelocks, escrows). Only use a real key when key-path spending is an
> intentional, documented feature of the contract.

---

### 3.8. `fees` Variable Convention

Section 4.3.C defines an implicit balance invariant:

```
SUM(INPUTS) == SUM(OUTPUTS) + fees
```

For this invariant to be verifiable by the compiler, the variable holding the miner fee
amount in the `calc` block MUST be **declared with the reserved name `fees`**. The
name `fees` is a normative identifier within the `calc` section. Any schema that performs
fee calculation MUST assign it to `fees`. Alternative names (e.g., `mining_fee`, `f`)
will cause the implicit balance check to be **skipped**, and `BTSL_WARN_06`
(`MISSING_FEES_DECLARATION`) MUST be emitted.

> This convention makes the fee calculation an explicit, auditable contract element
> rather than an opaque internal variable.

# 4. Semantics and Runtime

The BTSL execution engine transforms a declarative schema into a compliant PSBT through
three sequential phases: **Binding**, **Calculation**, and **Validation**.

## 4.1. Primitives Dictionary (Runtime Keywords)

| Keyword         | Type      | Description                                                                                     |
| :-------------- | :-------- | :---------------------------------------------------------------------------------------------- |
| `CURRENT_PSBT`  | Context   | Reference to the transaction object currently being constructed.                                |
| `vSize(PSBT)`   | Function  | Calculates the virtual size in vbytes using the canonical weight model (§3.5). **Formula:** `vsize = ceil(tx_weight / 4)`, where `tx_weight` is computed per §3.5.1. The `CURRENT_PSBT` argument instructs the compiler to use the transaction being built. |
| `REF(ref)`      | Function  | Forces an on-chain query to the indexer for the resolved value of `ref`. Accepted arguments: `compile_ref` (fetches the live UTXO value) or `workflow_ref` (fetches the confirmed output value of a previously broadcast schema transaction). See §4.2. |
| `SUM(INPUTS)`   | Function  | **Global aggregator:** sums the `amount` property of all UTXOs declared in the `INPUTS` section. Requires full resolution of all inputs. Any unresolved input raises `BTSL_ERR_05`. |
| `SUM(OUTPUTS)`  | Function  | **Global aggregator:** sums the `amount` value of all outputs declared in the `OUTPUTS` section. Used in the implicit balance check (§4.3.C). |
| `SUM(LIST.prop)`| Function  | **Iterative aggregator:** sums the `prop` property of all elements within a `FOREACH` collection. **Reserved:** available only when `FOREACH` is normatively defined (post-v1.0). |
| `COUNT(target)` | Function  | **Counter:** returns the number of elements in `target` as an `INT`. Accepted arguments: `INPUTS` (number of inputs), `OUTPUTS` (number of outputs), or a `PASCAL_CASE_ID.prop` path within a `FOREACH` collection (reserved). Returns `INT`, not `SAT`. |
| `DUST_LIMIT`    | Constant  | **Built-in constant:** 546 sats. This is the standard P2PKH dust threshold as enforced by Bitcoin Core relay policy. It MAY be overridden by a `CONST:` declaration in the schema; if overridden, the declared value takes precedence within that schema. |
| `NUMS_KEY`      | Constant  | The standard NUMS secp256k1 point (BIP341 §Appendix A). Disables key-path spending when used as `internal_key`. See §3.7. |
| `CHANGE`        | Keyword   | Marks an output as the change output. **Semantics:** (1) The compiler MUST include this output in `SUM(OUTPUTS)` for the balance check. (2) The `amount` argument MUST be a `snake_case_id` variable resolved from `calc` — a literal integer is NOT permitted. This requirement ensures the change amount is auditable and not hardcoded. |
| `Amount`        | Type Rule | Any value declared with the `btc` unit suffix is normalized to `sats` (× 100,000,000) at parse time. An `amount` field without an explicit unit suffix is treated as `sats`. All `calc` and `ASSERT` operations are executed exclusively in `sats`. |
| `From(@PUBKEY) AS alias` | Resolver | Resolves one UTXO from a `Pubkey`-typed `@PARAM` during the **Binding** phase (step 2 of the pipeline, §3.4). Derives the address from `@PUBKEY` using the type declared by `native_input_type` on the input (`NATIVE P2WPKH`, `NATIVE P2PKH`, etc.), or Taproot key-path (P2TR) by default. Performs an indexer list-query to enumerate confirmed UTXOs for the derived address and selects the **largest by amount** (largest-first). The selected UTXO is bound under `alias` in the binding context: `alias.amount` is accessible in `calc` as a `SAT` integer; `alias.address` is accepted as an `address_ref` in `OUTPUTS`. If no confirmed UTXO is found → `BTSL_ERR_09`. If `native_input_type` is absent → `BTSL_WARN_08`. The alias is **mandatory** — omitting `AS alias` → `BTSL_ERR_00`. See §4.5. |

---

## 4.2. Reference Categories

The runtime processes references according to their resolution mode to guarantee
consistency of multi-PSBT workflows:

1. **Compile-time (`@PARAM`):** Values bound from the `.params` file at step 2 of the
   pipeline (§3.4). Examples: `FEERATE`, `ADDRESS`, `UTXO` outpoint.

2. **On-chain (`REF()`):** Forces a live query to the network indexer (step 4 of the
   pipeline). REF() guarantees that the value used in `calc` or `ASSERT` is the
   **actual on-chain value**, not the value declared in the PSBT by the coordinator.
   This is the primary defense against a malicious coordinator injecting incorrect UTXO
   amounts.

   - `REF(@PARAM)` — Resolves the live on-chain UTXO for the `@PARAM` binding.
     Example: `REF(@BOB_UTXO.amount)` fetches the confirmed satoshi value of Bob's UTXO.
   - `REF(SCHEMA:idx.prop)` — Resolves the confirmed output of a previously broadcast
     schema transaction. Example: `REF(VAULT_DEPOSIT:0.amount)` fetches the confirmed
     amount of output 0 of the VAULT_DEPOSIT transaction.

3. **Workflow-time (`SCHEMA:idx.prop`):** Sequentially resolved from outputs of prior
   transactions in a multi-PSBT workflow. A `workflow_ref` used **without** `REF()` is
   resolved from the PSBT data structures (local state); it does not force an indexer
   query. Use `REF(workflow_ref)` when the live on-chain value must be verified.

> **Security implication:** In the Audit & Signature Workflow (§9.3), the Checker MUST
> use `REF()` to re-fetch all UTXO values from the chain. Values declared in
> `witness_utxo` / `non_witness_utxo` by the coordinator MUST be treated as untrusted
> until confirmed against `Blockchain_Value`.

---

## 4.3. Compilation Lifecycle (Pipeline)

### A. Binding & Inference

- **Flexible Mode:** If a `@PARAM` type is omitted, the wallet infers the script type
  from the actual `scriptPubKey` of the provided UTXO. A `BTSL_WARN_03` is emitted.
- **Constrained Mode:** If a `pubkey` or `script` is anchored via `SCRIPT_DEFS` or
  `@PARAMS`, the compiler MUST cryptographically verify that the `scriptPubKey` of the
  provided UTXO is derivable from that constraint. Mismatch raises `BTSL_ERR_02`.

> **`From()` Resolver:** When an input declares `utxo: From(@PUBKEY) AS alias`, the
> resolver executes during the Binding phase (step 2, §3.4), before `calc`. The
> compiler MUST treat `@PUBKEY` as a `Pubkey`-typed `@PARAM` and derive the address
> according to the `native_input_type` hint on the input: if present (`NATIVE P2WPKH`,
> `NATIVE P2PKH`, etc.), that type determines the address encoding; if absent, the
> compiler MUST derive a P2TR key-path address by default and emit `BTSL_WARN_08`. The
> resolver performs an indexer list-query (distinct from the `REF()` point-query) to
> enumerate confirmed UTXOs for the derived address, selects the one with the highest
> `amount` (largest-first), and registers the result in the binding context under
> `alias`. From that point forward, `alias.amount` is available in `calc` via
> `alias_ref`, and `alias.address` is accepted as an `address_ref` in `OUTPUTS`. The
> selected `txid:vout` MUST be persisted in the binding context so the Checker can
> replay `calc` and `ASSERT` against the same UTXO. See §4.5.

### B. Calculation Engine (`calc`)

1. **Sequential resolution:** Variables are resolved in **declaration order**. Any
   reference to a `calc` variable not yet declared in the current `calc` block raises
   `BTSL_ERR_04d` (`FORWARD_REFERENCE_IN_CALC`).

   > Note: `BTSL_ERR_04d` is distinct from `BTSL_ERR_04b` (`UNDECLARED_PARAM`), which
   > applies exclusively to missing `@PARAM` declarations.

2. **Async-Ready Management:** If a `calc` variable depends on an unresolved
   `workflow_ref` (parent TX not yet broadcast), the `calc` block is marked
   `Async-Ready` and deferred. If the runtime attempts to force execution of an
   `Async-Ready` block without prior resolution, it MUST raise `BTSL_ERR_05`.

3. **Unit normalization:** The compiler MUST normalize any `btc` value to `sats` during
   the parse phase. The BTSL runtime is unit-agnostic: it manipulates `SAT` integers
   exclusively. Arithmetic on non-normalized or invalid values MUST raise `BTSL_ERR_08`.

4. **`fees` convention:** The variable named `fees` is the **normative fee variable**.
   If present in `calc`, the compiler MUST use its value in the implicit balance check
   (§4.3.C). If absent, `BTSL_WARN_06` is emitted and the balance check is skipped.

### C. Validation (`ASSERT`)

The engine executes `ASSERT` statements in numerical index order (0 to N).

- Any failure triggers `BTSL_ERR_06`.
- If `ASSERT` indices are non-sequential (e.g., `0, 2, 5`), `BTSL_WARN_02` is emitted,
  but execution proceeds in the order of the declared indices.
- `ASSERT` is OPTIONAL. If absent, no business logic validation is performed.
- If present, **all assertions MUST be evaluated**; partial execution is strictly
  prohibited.

**Implicit Balance Check:**

If a `calc` variable named `fees` is declared, the compiler MUST verify:

```
SUM(INPUTS) == SUM(OUTPUTS) + fees
```

This check is **implicit and non-declarable**: it MUST NOT be possible for a schema
author to disable it via any syntax. It is executed as the final step of the `ASSERT`
phase, after all explicit `ASSERT` statements. A violation raises `BTSL_ERR_06`.

> `SUM(INPUTS)` requires all input UTXOs to be fully resolved via `REF()` on the Checker
> side. A partial resolution state raises `BTSL_ERR_05`.

---

## 4.4. Semantics: `calc` (Oracle) vs. `ASSERT` (Enforcer)

BTSL distinguishes between two logical roles to guarantee integrity:

- **`calc` (Internal Oracle):** Derives the expected contractual values (e.g., `fees`,
  `change_amount`). It is deterministic and MUST NOT generate business errors, except
  for runtime arithmetic exceptions (`BTSL_ERR_08`). The `calc` block represents "what
  the transaction *should* contain."

- **`ASSERT` (Enforcer):** Compares derived contractual values (`calc`) against the
  physical values present in the PSBT fields. **`ASSERT` is the sole component
  authorized to halt the machine with a business logic error.** If the actual on-chain
  or PSBT data diverges from the `calc` result, `ASSERT` raises `BTSL_ERR_06`. This
  separation enables granular auditability: it distinguishes a business logic violation
  from a transaction construction error.

---

## 4.5. `From()` — UTXO Resolver Semantics

### 4.5.1. Purpose

`From(@PUBKEY) AS alias` resolves a live UTXO from a `Pubkey` parameter without
requiring the schema author to specify a `txid:vout` manually. It is the ergonomic
bridge between a public key identity and a spendable UTXO.

### 4.5.2. Execution Phase

`From()` executes during the **Binding** phase (step 2 of the pipeline in §3.4),
alongside `@PARAM` resolution — not during `calc`. Its result is a fully resolved
UTXO object, treated identically to a `@PARAM:UTXO` binding for all subsequent
pipeline steps.

### 4.5.3. Address Derivation

The compiler derives the address to query from the `Pubkey` value according to
the following rules:

1. If `native_input_type` is declared on the input (`NATIVE P2WPKH`,
   `NATIVE P2PKH`, etc.), the compiler MUST derive the address for that
   script type only.
2. If `native_input_type` is absent, the compiler MUST derive a P2TR key-path
   address (BIP341) by default and emit `BTSL_WARN_08` to signal automatic
   inference.

### 4.5.4. Selection Strategy

The compiler queries the indexer for all **confirmed** UTXOs at the derived
address and selects the one with the **largest amount** (largest-first).

If no confirmed UTXO is available, the resolver MUST raise `BTSL_ERR_09`.

> **Design rationale:** The selection is intentionally not globally deterministic
> across runs. This is not a flaw — it is consistent with the BTSL enforcement
> model. `calc` and `ASSERT` define what constitutes a valid UTXO for this schema.
> Any UTXO that passes both is contractually correct, regardless of which specific
> UTXO was selected. The selected UTXO is recorded in the binding context and
> shared as part of the Truth Triplet (§9.1), allowing the Checker to replay
> `calc` and `ASSERT` against the same value.

### 4.5.5. Alias Binding and `calc` / `OUTPUTS` Exposure

The `AS alias` clause is **mandatory**. It binds the selected UTXO under `alias`
and exposes the following expressions:

| Expression      | Context   | Type      | Value                                                      |
| :-------------- | :-------- | :-------- | :--------------------------------------------------------- |
| `alias.amount`  | `calc`    | `SAT`     | Confirmed on-chain satoshi value of the selected UTXO      |
| `alias.address` | `OUTPUTS` | `ADDRESS` | Derived address of the selected UTXO (via `alias_ref`)     |

`alias.amount` and `alias.address` are syntactically represented via the `alias_ref`
production in the grammar (§2). No other properties are exposed.

### 4.5.6. Constraints

- The `@PARAM` passed to `From()` MUST be declared as `@X:Pubkey` in the
  `PARAMS:` section and MUST NOT include a property suffix (no `.amount`,
  `.txid`, etc.). Any other type or malformed value raises `BTSL_ERR_04e`.
- The `AS alias` clause is **mandatory**. Omitting it is a syntax error
  (`BTSL_ERR_00`).
- `From()` is only valid in a `simple_input_block` (`utxo:` field). Its use in
  an `unlock_block`, in `calc`, or in `ASSERT` is a syntax error (`BTSL_ERR_00`).

---

# 5. Security, Compatibility & Error Codes

## 5.1. Security Protocol (Multi-Party Security)

### 5.1.1. Cryptographic Binding Rule (Responsibility)

The role label (`ROLE_BUYER`, `ROLE_SELLER`, etc.) is not a mere annotation.

- **Flexible Mode:** If no public key or script is anchored, the role is purely
  functional. The wallet may assign any UTXO from the portfolio, provided that the
  script type (P2TR, P2WPKH, etc.) matches. The responsibility for selection lies with
  the user via the wallet's binding UI.

- **Constrained Mode (Anchored):** If a `pubkey` is anchored via `SCRIPT_DEFS` or
  `@PARAMS`, the compiler MUST verify that the `scriptPubKey` of the provided UTXO is
  derivable from that constraint. Failure raises `BTSL_ERR_02`.

### 5.1.2. Non-Repudiation Rule

The BTSL protocol delegates UI management to the wallet.

- The wallet MUST require **explicit confirmation** for each role-to-UTXO assignment.
- In the event of a role inversion (intentional or accidental), the transaction will be
  invalid at the Bitcoin network level (Script/Signature Failure), as the cryptographic
  proofs of possession (private keys) will fail to validate the `scriptPubKey` of the
  opposing UTXOs. **This is a business logic error, not a protocol flaw.**

### 5.1.3. Residual Risk (RBF / Txid Malleability) [OPEN]

**Note:** In the absence of `SIGHASH_ANYPREVOUT` (BIP118) or `OP_CHECKTEMPLATEVERIFY`
(BIP119), there is no complete mitigation against the mutation of a parent transaction's
`txid` via RBF (Replace-By-Fee). The BTSL protocol considers this a **structural,
accepted risk** and makes the following normative recommendations for dependent
transactions:

- Use `nLocktime` set to the current block height to create a temporal anchor.
- Use CPFP (Child-Pays-For-Parent) rather than RBF for fee bumping on parent
  transactions that are referenced by a `workflow_ref`.

---

## 5.2. BIP174/370 Compatibility (PSBT)

### 5.2.1. `PSBT_GLOBAL_UNKNOWN` Namespace Mapping

BTSL metadata MAY be attached to a PSBT via the `PSBT_GLOBAL_UNKNOWN` field as defined
in BIP174. This mechanism is an **optional portability aid**, not a logical requirement.
The `.bts` schema file remains the normative reference. A PSBT without these fields is
fully valid.

**Encoding:** BTSL proprietary keys use the following layout:

```
key   = 0xFC          (* BIP174 proprietary key type *)
      | varint(4)      (* key length: 4 bytes for the "BTSL" prefix *)
      | 0x42 0x54 0x53 0x4C  (* "BTSL" in ASCII *)
      | varint(len(subtype))
      | subtype        (* UTF-8 string identifying the BTSL field *)

value = varint(len(data)) | data
```

Defined subtypes:

| Subtype string | Content                                       |
| :------------- | :-------------------------------------------- |
| `"schema"`     | The `.bts` schema file content (UTF-8)        |
| `"params_hash"`| SHA-256 hash of the `.params` file (32 bytes) |
| `"version"`    | BTSL version integer as a 4-byte little-endian |

> Implementors MUST follow the `varint` encoding defined in BIP174 (Bitcoin compact size
> integer). Unknown subtypes MUST be ignored.

### 5.2.2. Forward Compatibility

Any BTSL compiler or parser encountering an unknown section MUST apply the extension
policy defined in §3.3:

- Unknown non-semantic sections (metadata, documentation): MAY emit `BTSL_WARN_01` and
  be silently ignored.
- Unknown semantic sections: MUST trigger `BTSL_ERR_00`.

Compilation MAY proceed **only if** all mandatory sections (`VERSION`, `INPUTS`,
`OUTPUTS`) are present and compliant, and no unknown semantic sections were encountered.

---

## 5.3. Error Code Table (BTSL_ERR_XX)

| Code           | Name                     | Cause                                                                                       |
| :------------- | :----------------------- | :------------------------------------------------------------------------------------------ |
| `BTSL_ERR_00`  | `SYNTAX_ERROR`           | Unparsable file: mixed indentation, missing `VERSION`, missing mandatory section, duplicate section. |
| `BTSL_ERR_01`  | `TYPE_MISMATCH`          | The injected UTXO does not match the declared type (`NATIVE` or `UNLOCK`).                 |
| `BTSL_ERR_02`  | `BINDING_FAILURE`        | The UTXO `scriptPubKey` does not match the `pubkey`/`script` anchored to the role.         |
| `BTSL_ERR_03`  | `CIRCULAR_DEPENDENCY`    | Mutual `DEPENDS_ON` detected (e.g., `A DEPENDS_ON B`, `B DEPENDS_ON A`).                   |
| `BTSL_ERR_04a` | `INVALID_DERIVED_FIELD`  | Manual input of a compiler-computed field (e.g., `control_block`).                         |
| `BTSL_ERR_04b` | `UNDECLARED_PARAM`       | Reference to a `@PARAM` not declared in the `PARAMS` section.                              |
| `BTSL_ERR_04c` | `INVALID_SCRIPT_TYPE`    | The `.script_type` property resolved to an unrecognized value.                             |
| `BTSL_ERR_04d` | `FORWARD_REFERENCE_IN_CALC` | A `calc` variable references another `calc` variable not yet declared in declaration order. |
| `BTSL_ERR_04e` | `INVALID_PUBKEY_PARAM`   | A `Pubkey`-typed `@PARAM` received a value that is not a valid 33-byte compressed secp256k1 public key (prefix `0x02` or `0x03`), or `From()` was invoked on a `@PARAM` not declared as `Pubkey`. |
| `BTSL_ERR_05`  | `UNRESOLVED_DEPENDENCY`  | `SUM()` or `REF()` called on an unresolved dependency (unbroadcast parent TX, or unfetched UTXO). |
| `BTSL_ERR_06`  | `ASSERT_FAILURE`         | An `ASSERT` condition evaluated to false, or the implicit balance invariant `SUM(INPUTS) != SUM(OUTPUTS) + fees` was violated. |
| `BTSL_ERR_07`  | `DUST_OUTPUT`            | Amount of a standard or `SCRIPT` output is below `DUST_LIMIT`.                             |
| `BTSL_ERR_08`  | `ARITHMETIC_ERROR`       | Runtime exception: division by zero, integer overflow, or a `SAT` value resolved to a negative integer. |
| `BTSL_ERR_09`  | `UTXO_RESOLUTION_FAILURE` | `From()` could not find any confirmed UTXO for the derived address of the given `Pubkey`. |
| `BTSL_ERR_10`  | `WITNESS_BINDING_MISMATCH` | A `witness_data` identifier does not match any placeholder name in the referenced `witness:` block, a placeholder has no corresponding `witness_data` entry, or the declaration order differs (P2TR paths with `witness:` only; see §2). |

---

## 5.4. Warning Table (BTSL_WARN_XX)

| Code            | Name                        | Cause                                                                                                   |
| :-------------- | :-------------------------- | :------------------------------------------------------------------------------------------------------ |
| `BTSL_WARN_01`  | `UNKNOWN_SECTION`           | An unknown or reserved section was encountered and ignored during compilation.                          |
| `BTSL_WARN_02`  | `NON_SEQUENTIAL_ASSERT`     | `ASSERT` indices are non-sequential (gaps detected). Execution proceeds in declared index order.        |
| `BTSL_WARN_03`  | `UNTYPED_PARAM`             | A `@PARAM` was declared without a type annotation. Fallback to Flexible Mode.                           |
| `BTSL_WARN_04` | `OP_RETURN_RELAY_RISK` | OP_RETURN payload exceeds 80 bytes.
|                |                        | Nodes running Bitcoin Core ≤ v29 or Bitcoin. Knots may reject this transaction. Payload is valid under Bitcoin Core v30+ default policy.                                |
| `BTSL_WARN_05`  | `KEY_PATH_ENABLED`          | A real (non-NUMS) key is used as `internal_key` in a `P2TR` script definition. Key-path spending is active. |
| `BTSL_WARN_06`  | `MISSING_FEES_DECLARATION`  | No `calc` variable named `fees` was found. The implicit balance invariant check is skipped.             |
| `BTSL_WARN_07`  | `EXCEEDS_STANDARD_WEIGHT`   | The computed `tx_weight` exceeds 400,000 wu. The transaction will likely be rejected by standard relay policy. |
| `BTSL_WARN_08`  | `INFERRED_PUBKEY_TYPE`      | `From()` was used without an explicit `native_input_type` hint. Address type was inferred automatically as Taproot key-path (P2TR) by default. Schema authors SHOULD declare `NATIVE` explicitly for deterministic type binding. |
| `BTSL_WARN_09`  | `CONST_SHADOWING`           | A local `CONST` declaration shadows a global `CONST` identifier of the same name. |

> **Implementer Note — Network Heterogeneity:** BTSL schemas using `OP_RETURN` payloads
> larger than 80 bytes are valid under Bitcoin Core v30+ default policy but will be
> rejected by a non-negligible fraction of the relay network. Schema authors SHOULD
> document this risk explicitly. The `BTSL_WARN_04` warning exists precisely to surface
> this heterogeneity at compile time.

---

# 6. Production Examples (Normative Appendix)

> All examples in this section are **normative**: they constitute compliance test targets.
> A conforming BTSL implementation MUST accept and correctly process each example.
> The `VERSION: 1` header is mandatory in all schema files (§3.1).

---

### 6.1. Tri-Count (Shared Payment)

*Demonstrates dynamic change calculation and global balance validation across multiple
payers.*

```bts
VERSION: 1

CONST:
    DUST_LIMIT = 546

PSBT_SCHEMA TRICOUNT:
    PARAMS:
        @BOB_UTXO:UTXO
        @CARO_UTXO:UTXO
        @ALICE_ADDRESS:ADDRESS
        @MAKER_ADDRESS:ADDRESS
        @FEE_RATE:FEERATE
        @MAKER_FEE:SATOSHI
        @MEAN:SATOSHI
        @A2:SATOSHI
        @A3:SATOSHI

    INPUTS:
        0:
            utxo: @BOB_UTXO
        1:
            utxo: @CARO_UTXO

    OUTPUTS:
        0: @ALICE_ADDRESS payment sats
        1: CHANGE @BOB_UTXO.address c_bob sats
        2: CHANGE @CARO_UTXO.address c_caro sats
        3: @MAKER_ADDRESS maker_fee_val sats

    calc:
        payment = (2 * @MEAN) - @A2 - @A3
        fees_btc = vSize(CURRENT_PSBT) * @FEE_RATE
        fees = @MAKER_FEE + fees_btc
        ; Mapping the @PARAM to snake_case for use in the OUTPUTS block
        maker_fee_val = @MAKER_FEE
        c_bob  = REF(@BOB_UTXO.amount) - (@MEAN - @A2) - (fees / 2)
        c_caro = REF(@CARO_UTXO.amount) - (@MEAN - @A3) - (fees / 2)

    ASSERT:
        0: c_bob >= DUST_LIMIT
        1: c_caro >= DUST_LIMIT
        2: payment > 0
        3: REF(@BOB_UTXO.amount) >= (@MEAN - @A2) + (fees / 2)
        4: REF(@CARO_UTXO.amount) >= (@MEAN - @A3) + (fees / 2)
```

> **Note on `fees`:** The variable `fees` aggregates both miner fees and the maker
> service fee. This is intentional: the implicit balance check (§4.3.C) will verify
> `SUM(INPUTS) == SUM(OUTPUTS) + fees`, which accounts for all satoshis leaving the
> inputs and not reaching the visible outputs.

---

### 6.2. Multisig 2-of-2 (Reusable Contract)

*Demonstrates `SCRIPT_DEFS` with P2WSH, the `<empty>` witness placeholder for
`OP_CHECKMULTISIG`, and constrained-mode binding.*

```bts
VERSION: 1

SCRIPT_DEFS:
    MULTISIG_2_2 P2WSH:
        asm: OP_2 <pubkey(PK1)> <pubkey(PK2)> OP_2 OP_CHECKMULTISIG

PSBT_SCHEMA MULTISIG_SPEND:
    PARAMS:
        @MULTISIG_UTXO:UTXO
        @DEST:ADDRESS
        @FEE_RATE:FEERATE
        @KEY1:HEX_DATA
        @KEY2:HEX_DATA

    INPUTS:
        0: UNLOCK MULTISIG_2_2:
            utxo: @MULTISIG_UTXO
            witness_data:
                ; OP_CHECKMULTISIG requires an OP_0 dummy as the first witness item
                ; (BIP147 note: this empty element is mandatory for P2WSH)
                DUMMY = <empty>
                SIG1  = <SIGN_WITH(@KEY1)>
                SIG2  = <SIGN_WITH(@KEY2)>

    OUTPUTS:
        0: @DEST 50000 sats
        1: CHANGE @MULTISIG_UTXO.address change_amount sats

    calc:
        fees = vSize(CURRENT_PSBT) * @FEE_RATE
        change_amount = REF(@MULTISIG_UTXO.amount) - 50000 - fees

    ASSERT:
        0: change_amount >= DUST_LIMIT
```

> **OP_CHECKMULTISIG dummy element:** Bitcoin Script has an off-by-one bug in the
> `OP_CHECKMULTISIG` opcode that consumes one extra stack element beyond the declared
> signatures. The convention is to push an empty byte array (`OP_0`) as the first
> witness item. Omitting this element causes a `Script evaluation failed` error on
> broadcast. The `<empty>` placeholder encodes this requirement explicitly in the schema.

---

### 6.3. OP_RETURN Deploy

*Demonstrates `OP_RETURN` metadata embedding and `NATIVE` type hint.*

```bts
VERSION: 1

CONST:
    DUST_LIMIT = 546

PSBT_SCHEMA OP_RETURN_DEPLOY:
    PARAMS:
        @USER:UTXO
        @PAYLOAD:HEX_DATA
        @FEE_RATE:FEERATE

    INPUTS:
        0: NATIVE P2WPKH
            utxo: @USER

    OUTPUTS:
        0: OP_RETURN @PAYLOAD
        1: CHANGE @USER.address change_amount sats

    calc:
        fees = vSize(CURRENT_PSBT) * @FEE_RATE
        change_amount = REF(@USER.amount) - fees

    ASSERT:
        0: change_amount >= DUST_LIMIT
```

---

### 6.4. Timelocked Vault (Two-Step Workflow)

*Demonstrates `SCRIPT_DEFS` with P2TR, `NUMS_KEY` for script-path-only spending,
`DEPENDS_ON` chaining, `sequence:` for CSV, and `REF(workflow_ref)`.*

```bts
VERSION: 1

SCRIPT_DEFS:
    VAULT_P2TR P2TR:
        ; NUMS_KEY disables key-path spending.
        ; The only valid spending path is unlock_path (timelocked).
        ; A BTSL_WARN_05 would be emitted if a real key were used here.
        internal_key: NUMS_KEY
        paths:
            unlock_path SCRIPT:
                leaf_version: 192
                witness:
                    <sig(USER_SIG)>
                asm: 100 OP_CSV OP_DROP <pubkey(USER_PK)> OP_CHECKSIG

PSBT_SCHEMA VAULT_DEPOSIT:
    PARAMS:
        @FUNDING_UTXO:UTXO
        @FEE_RATE:FEERATE
        @KEY_PUB:HEX_DATA

    INPUTS:
        0: NATIVE P2WPKH
            utxo: @FUNDING_UTXO

    OUTPUTS:
        0: SCRIPT VAULT_P2TR 100000 sats
            script_params:
                USER_PK = @KEY_PUB
        1: CHANGE @FUNDING_UTXO.address change_amount sats

    calc:
        fees = vSize(CURRENT_PSBT) * @FEE_RATE
        change_amount = REF(@FUNDING_UTXO.amount) - 100000 - fees

    ASSERT:
        0: change_amount >= DUST_LIMIT


PSBT_SCHEMA VAULT_UNLOCK:
    OPTIONS:
        DEPENDS_ON VAULT_DEPOSIT

    PARAMS:
        @USER_ADDR:ADDRESS
        @FEE_RATE:FEERATE
        @USER_KEY:HEX_DATA
        @KEY_PUB:HEX_DATA

    INPUTS:
        0: UNLOCK VAULT_P2TR USING unlock_path:
            utxo: VAULT_DEPOSIT:0.txid:0
            ; sequence: 100 encodes a BIP68 block-based relative timelock of 100 blocks.
            ; The compiler MUST set PSBT_IN_SEQUENCE = 100 (0x00000064).
            ; Bit 31 (disable flag) and bit 22 (time-based flag) MUST be clear.
            ; See §9.5 for nSequence encoding normative rules.
            sequence: 100
            script_params:
                USER_PK = @KEY_PUB
            witness_data:
                USER_SIG = <SIGN_WITH(@USER_KEY)>

    OUTPUTS:
        0: @USER_ADDR final_payout sats

    calc:
        fees = vSize(CURRENT_PSBT) * @FEE_RATE
        ; REF() forces an on-chain query to confirm the vault output value.
        ; Using a bare workflow_ref here without REF() would trust the PSBT data.
        final_payout = REF(VAULT_DEPOSIT:0.amount) - fees

    ASSERT:
        0: final_payout > DUST_LIMIT
```

---

### 6.5. Single-Key Spend via `From()` (Pubkey Resolver)

*Demonstrates `From()` with mandatory `AS` alias, `Pubkey` param type,
`NATIVE P2WPKH` declaration suppressing `BTSL_WARN_08`, and local `CONST:` scope.*

```bts
VERSION: 1

CONST:
    DUST_LIMIT = 330

PSBT_SCHEMA PUBKEY_SPEND:
    CONST:
        PAYMENT_ADDRESS = "bc1pw05kccyprc9uk0l32zaegva2rh68c6ra08n6zuhwzjsyapqhusss59usvt"
        AMOUNT = 10000

    PARAMS:
        @PUBKEY:Pubkey
        @FEE_RATE:FEERATE

    INPUTS:
        0: NATIVE P2WPKH
            utxo: From(@PUBKEY) AS selected_utxo

    OUTPUTS:
        0: PAYMENT_ADDRESS AMOUNT sats
        1: CHANGE selected_utxo.address change_amount sats

    calc:
        fees = vSize(CURRENT_PSBT) * @FEE_RATE
        change_amount = selected_utxo.amount - AMOUNT - fees

    ASSERT:
        0: change_amount >= DUST_LIMIT
```

> **`NATIVE P2WPKH` declaration** suppresses `BTSL_WARN_08` and instructs the
> compiler to derive the P2WPKH address from `@PUBKEY` for the indexer query.
> Without this declaration, the compiler would default to P2TR derivation and
> emit `BTSL_WARN_08`.
>
> **`selected_utxo.amount`** is the confirmed on-chain value of the UTXO
> selected by `From()` (largest-first strategy). It is resolved at bind time
> (step 2 of the pipeline) and available as a `SAT` integer throughout `calc`
> and `ASSERT`.
>
> **`selected_utxo.address`** is used in the `CHANGE` output via `alias_ref`.
> This ensures the change is returned to the same derived address without
> requiring the author to pass it as a separate `@PARAM`.

---

# 7. Test Suite (Test Vectors)

This suite validates the BTSL engine (compiler and runtime). All implementations MUST
pass these vectors to be considered compliant.

**Standardized test keys (BIP32 Test Vector 1, `m/0'`):**

- `PK_A`: `0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2`
- `UTXO_A`: `0000000000000000000000000000000000000000000000000000000000000000:0`

---

### 7.1. Structural Vectors (Parsing)

| ID        | Scenario                                       | Runtime Behavior                | Expected       |
| :-------- | :--------------------------------------------- | :------------------------------ | :------------- |
| **ST-01** | Mixed indentation (tabs and spaces)            | Rejected by Lexer               | `BTSL_ERR_00`  |
| **ST-02** | `SCRIPT_DEFS` block without `asm`              | Incomplete definition           | `BTSL_ERR_00`  |
| **ST-03** | Untyped `@PARAM`                               | Fallback to Flexible Mode       | `BTSL_WARN_03` |
| **ST-04** | Typed `@PARAM`                                 | Constrained Mode (Binding)      | `VALID`        |
| **ST-05** | `ASSERT` indices `0, 2, 5` (gaps)              | Sequential exec, gaps warned    | `BTSL_WARN_02` |
| **ST-06** | Schema without `VERSION:` header               | Rejected                        | `BTSL_ERR_00`  |
| **ST-07** | Duplicate `INPUTS:` section in one `PSBT_SCHEMA` | Rejected                      | `BTSL_ERR_00`  |
| **ST-08** | `RESERVED` section present (`FOREACH`, `IMPORT`, `REQUIRED`) | Warned, ignored | `BTSL_WARN_01` |
| **ST-09** | `From(@PUBKEY) AS alias` without `native_input_type` on the input | Binding succeeds, P2TR address inferred | `BTSL_WARN_08` |
| **ST-10** | `From(@PUBKEY)` without `AS alias` clause | Rejected at parse time | `BTSL_ERR_00` |
| **ST-11** | `From(@PARAM)` where `@PARAM` is not declared as `Pubkey` | Rejected at bind time | `BTSL_ERR_04e` |

---

### 7.2. Logical Vectors (Runtime & Calc)

| ID        | Scenario                                              | Expected       | Reason                                                  |
| :-------- | :---------------------------------------------------- | :------------- | :------------------------------------------------------ |
| **LG-01** | `SAT` variable resolves to a negative integer in `calc` | `BTSL_ERR_08` | SAT domain violation (§3.6.C): negative integers are arithmetic errors, not assertion failures. |
| **LG-02** | `change_amount` < `DUST_LIMIT` with explicit `ASSERT` | `BTSL_ERR_06` | Assertion violation.                                    |
| **LG-03** | `SUM(INPUTS) != SUM(OUTPUTS) + fees`                  | `BTSL_ERR_06` | Implicit balance invariant violated (§4.3.C).           |
| **LG-04** | `REF()` called on unbroadcast parent TX               | `BTSL_ERR_05` | Unresolved dependency.                                  |
| **LG-05** | Division by zero in `calc`                            | `BTSL_ERR_08` | Arithmetic exception.                                   |
| **LG-06** | `SCRIPT` output amount < `DUST_LIMIT`                 | `BTSL_ERR_07` | Dust output violation.                                  |
| **LG-07** | Forward reference in `calc` (variable used before declaration) | `BTSL_ERR_04d` | Forward reference in `calc` block (§4.3.B). |
| **LG-08** | `OP_RETURN` payload 81 bytes                          | `BTSL_WARN_04` | Exceeds standard relay limit.                           |
| **LG-09** | `tx_weight` > 400,000 wu                              | `BTSL_WARN_07` | Exceeds standard relay weight policy.                   |
| **LG-10** | `@PARAM` reference without `PARAMS:` section          | `BTSL_ERR_04b` | Undeclared param.                                       |
| **LG-11** | `From(@PUBKEY)` where the derived address has no confirmed UTXOs | `BTSL_ERR_09` | Resolver found no candidate UTXO for the given `Pubkey` (§4.5.4). |

---

### 7.3. Cryptographic Vectors (Binding)

| ID        | Scenario                                              | Expected       | Reason                                            |
| :-------- | :---------------------------------------------------- | :------------- | :------------------------------------------------ |
| **CR-01** | UTXO injection where `scriptPubKey` ≠ derived from `PK_A` | `BTSL_ERR_02` | `BINDING_FAILURE`.                           |
| **CR-02** | Signature with `PK_A` on correctly bound role         | `VALID`        | Compliant proof of possession.                    |
| **CR-03** | Signature with unbound key `PK_C`                     | `BTSL_ERR_02`  | Key not recognized by role binding.               |
| **CR-04** | P2TR script definition with `internal_key: NUMS_KEY`  | `VALID`        | No warning. Key-path spending is disabled.        |
| **CR-05** | P2TR script definition with `internal_key: PLATFORM_PK` | `BTSL_WARN_05` | Key-path enabled, warning emitted.              |

---

### 7.4. Weight Model Vectors

These vectors validate the canonical weight calculation (§3.5).

| ID        | Transaction Structure                                    | Expected `tx_weight` (wu) | Expected `vsize` (vB) |
| :-------- | :------------------------------------------------------- | :------------------------ | :-------------------- |
| **WM-01** | 1 P2WPKH input, 1 P2WPKH output, 1 P2TR output          | 42 + 273 + 124 + 172 = 611 wu | ceil(611/4) = 153 vB |
| **WM-02** | 1 P2TR_KEY input, 1 P2TR output                          | 42 + 230 + 172 = 444 wu   | ceil(444/4) = 111 vB  |
| **WM-03** | 1 P2PKH input, 1 P2PKH output (legacy, no segwit)        | 40 + 592 + 136 = 768 wu   | ceil(768/4) = 192 vB  |

> Implementations MUST produce these exact values. Deviations indicate an incorrect
> weight model implementation.

---

# 8. Implementation Checklist

### A. Parsing & Lexer

- [ ] Lexer: explicit `INDENT` / `DEDENT` + `NL` handling (`\n` and `\r\n`).
- [ ] Mixed indentation detection → `BTSL_ERR_00`.
- [ ] Reserved keyword list enforced (§2, RESERVED KEYWORDS).
- [ ] `COMMENT` delimiter: `;` (semicolon).
- [ ] Support for `asm_inline` (space-delimited) and `asm_multiline` (indented).
- [ ] Automatic `btc` → `sats` (× 100,000,000) normalization at parse time.
- [ ] `amount` without unit suffix treated as `sats`.
- [ ] Support for the `.params` format: UTF-8, `key=value`, one entry per line, `#` for comments.
- [ ] `VERSION:` header validation → `BTSL_ERR_00` if absent.
- [ ] Duplicate section detection within a single `PSBT_SCHEMA` → `BTSL_ERR_00`.
- [ ] Reserved sections (`FOREACH`, `IMPORT`, `REQUIRED`) → `BTSL_WARN_01`.

### B. Execution Engine & Runtime

- [ ] **Canonical weight model (§3.5):** implement all weight tables in **wu**.
  - `BASE_TX_OVERHEAD = 40 wu`
  - `SEGWIT_OVERHEAD = 2 wu` (conditional, if any segwit input present)
  - Input weights per §3.5.3 table.
  - Output weights per §3.5.4 table.
  - `control_block_weight(depth) = 34 + (32 × depth)` wu.
  - `vsize = ceil(tx_weight / 4)` — single rounding operation.
- [ ] Resolution of `workflow_ref` (`SCHEMA:idx.txid:vout`).
- [ ] `REF()` accepts both `compile_ref` and `workflow_ref` as arguments.
- [ ] `Async-Ready` state for `calc` deferred blocks → `BTSL_ERR_05` on forced execution.
- [ ] Arithmetic: standard operator precedence (`*` and `/` before `+` and `-`).
  Capture `BTSL_ERR_08` for division by zero, negative SAT, and overflow.
- [ ] `SUM(INPUTS)` (global) vs. `SUM(LIST.prop)` (reserved/iterative).
- [ ] `COUNT(INPUTS)` and `COUNT(OUTPUTS)` return `INT`.
- [ ] `fees` variable convention: emit `BTSL_WARN_06` if `fees` is absent from `calc`.
- [ ] Implicit balance check: `SUM(INPUTS) == SUM(OUTPUTS) + fees` → `BTSL_ERR_06` on violation.
- [ ] `CHANGE` keyword: the `amount` argument MUST be a `calc` variable, not a literal.
- [ ] `DUST_LIMIT` built-in constant = 546 sats (overridable via `CONST:`).
- [ ] `NUMS_KEY` built-in constant = `0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`.
- [ ] `From()` UTXO resolver: `Pubkey` address derivation (P2TR default / `NATIVE` override), largest-first selection, mandatory `AS alias`, `alias.amount` in `calc`, `alias.address` in `OUTPUTS`. Raise `BTSL_ERR_09` if no confirmed UTXO found; emit `BTSL_WARN_08` if type inferred.
- [ ] Witness nominal binding (P2TR paths with `witness:` only): each `witness_data` assignment MUST match exactly (case-sensitive, same order) the `witness_placeholder` names in the referenced path’s `witness:` block; raise `BTSL_ERR_10` on mismatch, missing entry, or order violation. Skip this check for P2WSH/P2SH unlocks without `witness:` placeholders.

### C. Security, Compliance & Errors

- [ ] Cryptographic validation: `scriptPubKey` derivation vs. anchored `pubkey`.
- [ ] `BTSL_WARN_05` emission when `internal_key` is not `NUMS_KEY` in a P2TR definition.
- [ ] `nSequence` encoding for `sequence:` field per BIP68 (§9.5).
- [ ] `<empty>` witness placeholder: pushes 0-byte item onto witness stack.
- [ ] `PSBT_GLOBAL_UNKNOWN` namespace injection per §5.2.1 encoding spec.
- [ ] Complete error table: `BTSL_ERR_00` through `BTSL_ERR_10` (including `04a`–`04e`).
- [ ] Complete warning table: `BTSL_WARN_01` through `BTSL_WARN_09`.
- [ ] RBF/CPFP recommendation: `nLocktime` on child transactions referencing `workflow_ref`.

---

# 9. Operational Workflow & Integrity

## 9.1. The Validation Triplet (Data Anchoring)

Any BTSL operation requires the **Truth Triplet**. All three components MUST be present
for a fully auditable transaction:

1. **PSBT** (BIP174/370) — the binary transaction object.
2. **`.bts`** — the BTSL schema file (normative reference).
3. **`.params`** — runtime binding file (UTF-8, `key=value`, one entry per line, `#` for comments).

---

## 9.2. Construction Workflow (Maker Side)

1. **Binding:** Resolution of `@PARAMS` from the `.params` file.
2. **Builder Engine:** Injection of `witnessUtxo` from an on-chain source. The
   `PSBT_IN_WITNESS_UTXO` field MUST be populated for all segwit inputs
   (BIP174 requirement). The `amount` value is fetched live via an indexer.
3. **Logical Injection:** Execution of `calc` in declaration order. Insertion of the
   computed payload into the PSBT structure.
4. **Serialization:** Base64 export of the finalized PSBT.

---

## 9.3. Audit & Signature Workflow (Checker Side)

1. **Extraction:** `bitcoin-cli decodepsbt` → JSON, or equivalent library call.
2. **Restoration (Anti-Fraud Step):** The Checker MUST ignore the `amount` declared
   in `witness_utxo` / `non_witness_utxo` fields by the coordinator. The actual
   on-chain value MUST be independently fetched (`prevout` query). **Strict validation
   required: `PSBT_IN_VALUE == Blockchain_Value`. Any discrepancy is fatal.**
3. **Replay Mode:** Re-execution of `calc` using the live on-chain values obtained
   in step 2. Comparison of computed `calc` variables against PSBT output amounts.
4. **Enforcement:** Full execution of `ASSERT` statements, followed by the implicit
   balance check. Any failure → `BTSL_ERR_06`. Execution halts immediately.
5. **Signature:** Authorization granted only after the successful completion of steps
   2, 3, and 4. No partial signing is permitted.

---

## 9.4. Multi-PSBT Security (Workflow Chaining)

- `DEPENDS_ON` validation: if the parent schema has not been broadcast, the child is
  placed in `PENDING` state. Any forced evaluation → `BTSL_ERR_05`.
- Chain integrity check:
  `PSBT_IN_PREV_TXID == REF(SCHEMA:idx.txid)` AND
  `PSBT_IN_PREV_VOUT == REF(SCHEMA:idx.vout)`
- Circular dependency detection: if `A DEPENDS_ON B` and `B DEPENDS_ON A` →
  `BTSL_ERR_03` immediately at the `OPTIONS` parse phase.

---

## 9.5. `nSequence` Encoding for `sequence:` (BIP68)

The `sequence:` field in a BTSL `unlock_block` maps to the `nSequence` field of the
corresponding PSBT input (`PSBT_IN_SEQUENCE`, BIP370 per-input key type `0x00`).

When used in conjunction with `OP_CSV`, the value MUST conform to BIP68 relative
timelock encoding:

- **Bit 31 (disable flag):** MUST be 0. If set to 1, the sequence number is treated as
  a non-timelock value and `OP_CSV` will fail.
- **Bit 22 (type flag):** If 0, the value encodes a **block count** (16-bit, bits 0–15).
  If 1, the value encodes a **512-second interval count** (16-bit, bits 0–15).
- **Valid range for block-based CSV:** 1 to 65535 blocks.

The compiler MUST validate that the `sequence:` value is consistent with the `OP_CSV`
operand in the associated `asm:` block. If they differ, the compiler MUST raise
`BTSL_ERR_01` (`TYPE_MISMATCH`).

> **Example:** `sequence: 100` → `nSequence = 0x00000064`. Bit 31 = 0, Bit 22 = 0,
> value = 100 blocks. The `asm:` block MUST contain `<100> OP_CSV` to match.

---

## 9.6. Non-Repudiation Rule

- **Binding UX:** The wallet MUST require explicit, informed confirmation for each
  role-to-UTXO assignment before constructing the PSBT.
- **Responsibility:** An assignment error produces a cryptographic failure at the
  Bitcoin network level (Script/Signature Failure). This provides natural fund
  protection. It is a business logic error, not a protocol flaw.

---

## 9.7. [OPEN] Future Work: Offline Audit & SPV Proofs (Air-Gapped Zero-Trust)

Currently, the audit protocol (§9.3, step 2) requires an active connection to an
on-chain indexer to validate the `Blockchain_Value` of a UTXO. This constrains strict
Zero-Trust enforcement for hardware wallets operating in fully isolated (Air-gapped)
environments.

To address this in a future iteration, integration of native **Merkle inclusion proof**
support (SPV — Simplified Payment Verification) is envisioned. This mechanism would
encapsulate the required block headers and Merkle branches directly within the PSBT or a
supplementary file. The embedded BTSL compiler could then hash the parent transaction
(via the BIP174 `non_witness_utxo` field), cryptographically verify its inclusion in a
valid block, and extract the UTXO value offline prior to resolving `ASSERT` clauses.

> **Community discussion:** Future maintainers are invited to define the optimal
> encapsulation format (new `PSBT_GLOBAL_UNKNOWN` subtypes or a coupled `.spv` sidecar
> file) and to evaluate the RAM footprint impact on hardware wallet microcontrollers.

