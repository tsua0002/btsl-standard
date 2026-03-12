# Example: Tri-Count Shared Payment

This example demonstrates how BTSL can encode the economic invariants of a shared-expense settlement into a declarative validation schema.

---

## Scenario

Three people — Alice, Bob, and Caro — went on a trip together. Over the course of the trip, each person paid for various expenses on behalf of the group:

| Person | Amount paid (`aᵢ`) |
|:-------|-------------------:|
| Alice  | `a₁`               |
| Bob    | `a₂`               |
| Caro   | `a₃`               |

They want to settle all debts in a **single Bitcoin transaction**, rather than exchanging multiple payments.

---

## The Settlement Algorithm

### Step 1 — Compute the fair share

Each person should have paid exactly one third of the total expenses:

```
mean = (a₁ + a₂ + a₃) / 3
```

This is the `@MEAN` parameter injected into the schema.

### Step 2 — Identify who receives and who pays

- Anyone who paid **more** than `mean` is owed money.
- Anyone who paid **less** than `mean` owes money.

**Assumption of this example (required for the schema to be valid):**

> Alice paid the most: `a₁ = max(a₁, a₂, a₃)`

This means Alice is owed money by both Bob and Caro. Alice therefore has **no change output** in the transaction — she only receives a payment.

If this assumption does not hold (i.e. Alice is not the max payer), `ASSERT 2` (`payment > 0`) will fail at validation time, refusing the signing.

### Step 3 — Compute what each debtor owes

Bob owes Alice the difference between his fair share and what he actually paid:

```
bob_owes = mean - a₂
```

Caro owes Alice the same logic:

```
caro_owes = mean - a₃
```

### Step 4 — Compute Alice's total payment

Alice receives the sum of what Bob and Caro owe her:

```
payment = bob_owes + caro_owes
        = (mean - a₂) + (mean - a₃)
        = 2·mean - a₂ - a₃
```

This is the `payment` variable in the `calc` block:

```
payment = (2 * @MEAN) - @A2 - @A3
```

---

## Fee Splitting

Transaction fees (miner fee + platform maker fee) are split equally between the two payers:

```
fees_sats     = vSize(CURRENT_PSBT) × @FEE_RATE
total_fees    = @MAKER_FEE + fees_sats
each_pays     = total_fees / 2
```

### Change outputs

After paying their debt to Alice and their share of fees, each payer receives a change output back to their own address:

```
c_bob  = UTXO_bob.amount  - (mean - a₂) - (total_fees / 2)
c_caro = UTXO_caro.amount - (mean - a₃) - (total_fees / 2)
```

---

## ASSERT Block — What is being enforced

| Assert | Condition                          | Purpose                                                      |
|:-------|:-----------------------------------|:-------------------------------------------------------------|
| 0      | `c_bob >= DUST_LIMIT`              | Bob's change output must be spendable                        |
| 1      | `c_caro >= DUST_LIMIT`             | Caro's change output must be spendable                       |
| 2      | `payment > 0`                      | Alice must be a net receiver (enforces the max assumption)   |
| 3      | `UTXO_bob.amount >= debt + fees`   | Bob's UTXO is sufficient to cover his obligations            |
| 4      | `UTXO_caro.amount >= debt + fees`  | Caro's UTXO is sufficient to cover her obligations           |

If any of these assertions fail, the schema validator refuses signing. No key material is used.

---

## Transaction Structure

```
INPUTS
  [0]  Bob's UTXO   (P2WPKH or P2TR)
  [1]  Caro's UTXO  (P2WPKH or P2TR)

OUTPUTS
  [0]  Alice's address     →  payment      (settlement)
  [1]  Bob's address       →  c_bob        (change)
  [2]  Caro's address      →  c_caro       (change)
  [3]  Maker address       →  maker_fee    (platform fee)
```

---

## Files

| File               | Description                                              |
|:-------------------|:---------------------------------------------------------|
| `schema.bts`       | BTSL schema defining the transaction invariants          |
| `example.params`   | Sample parameter values for testing and validation       |

---

## Notes

- The schema accepts both P2WPKH and P2TR inputs interchangeably. The wallet resolves the scriptPubKey from the UTXO at injection time.
- The `@MEAN` parameter must be pre-computed off-chain and injected explicitly. The schema validates that the PSBT is consistent with it — it does not recompute it from raw amounts.
- This example assumes a two-payer topology. Generalizing to `n` payers would require extending the `INPUTS`, `OUTPUTS`, and `calc` blocks accordingly.
