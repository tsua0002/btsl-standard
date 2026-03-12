# BTSL Examples

The `examples/` folder contains **normative** BTSL schemas and template `.params` files
corresponding to §6 ("Production Examples") of the BTSL v1.0 specification.

Each subfolder contains:

- `schema.bts` — a direct extraction of the normative example from `spec/btsl-spec-v1.0.md`.
- `example.params` — a `.params` template showing how to bind all `@PARAMS`.

> **Safety note:** All `.params` files use obviously fake UTXOs and addresses.
> They are intended for parser/runtime testing, not for real fund movements.
> Replace them with your own testnet/regtest bindings before constructing or signing PSBTs.

## Scenario Index

- `tri-count-shared-payment/`
  - **Schema:** §6.1 `TRICOUNT` — shared payment with dynamic change and maker fee.
  - **Focus:** multi-party fee sharing, `REF(@PARAM.amount)`, implicit balance via `fees`.

- `multisig-2-of-2/`
  - **Schema:** §6.2 `MULTISIG_SPEND` — 2-of-2 P2WSH multisig.
  - **Focus:** `SCRIPT_DEFS` P2WSH, `<empty>` witness placeholder for `OP_CHECKMULTISIG`,
    constrained-mode binding.

- `op-return-deploy/`
  - **Schema:** §6.3 `OP_RETURN_DEPLOY` — metadata embedding via `OP_RETURN`.
  - **Focus:** `HEX_DATA` payloads, `OP_RETURN` output type, change handling.

- `timelocked-vault/`
  - **Schema:** §6.4 `VAULT_DEPOSIT` / `VAULT_UNLOCK` — P2TR timelocked vault.
  - **Focus:** `NUMS_KEY` for script-path-only Taproot, `DEPENDS_ON` chaining,
    `sequence:`/`OP_CSV` semantics, `REF(workflow_ref)`.

- `single-key-from-pubkey/`
  - **Schema:** §6.5 `PUBKEY_SPEND` — single-key spend via `From(@PUBKEY) AS alias`.
  - **Focus:** `Pubkey` parameter type, `From()` resolver semantics, `alias.amount` in `calc`,
    `alias.address` in `OUTPUTS`, interaction with `native_input_type`.

