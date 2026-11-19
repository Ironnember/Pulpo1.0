# Lesson 01 — Reliable financial records, not automatic payments

**Track:** beginner Python / source-grounded finance / Pulpo boundary literacy. **Safe surface:** pure synthetic records, no bank, network, provider, filesystem, credentials, user accounts or execution permit.

**Read:** [Automate 3e chapter 1](https://automatetheboringstuff.com/3e/chapter1.html) on values, [chapter 5](https://automatetheboringstuff.com/3e/chapter5.html) on error handling, [chapter 18](https://automatetheboringstuff.com/3e/chapter18.html) on JSON and CSV. Compare financial goals described in [Aliche's official excerpt](https://www.penguinrandomhouse.com/articles/get-good-with-money-excerpt/) and [the ten-level Joy of Money program](https://thejoyofmoney.com/).

## Goal

Given a synthetic potential business expense, distinguish three independent claims:

1. **Input quality:** Is the decimal amount correctly represented? Is the complete source record identified?
2. **Budget suitability:** Does a hypothetical amount lie below a declared policy *suggestion* ceiling?
3. **Authority and reality:** Who approved the exact action? Did the intended provider receive it, and is there independent observation? **Neither of those last two is present in this exercise.**

## Do this

Run from the repository root:

```shell
python3 -m unittest discover -s docs/learning/examples -p 'test_lab01.py' -v
python3 docs/learning/examples/lab01.py
```

The example constructs and hashes a proposal but has no send or transfer function. See [lab01.py](examples/lab01.py) and [negative tests](examples/test_lab01.py). It does not grant Pulpo authority; don't insert it into `pulpo/` or `custody-service/` as a production component.

## Deliberately hostile cases

- A numeric `float`, a boolean, a negative amount, or a string with more than two decimals: reject instead of rounding or coercing.
- Missing currency or an unexpected extra field: reject rather than silently expanding the meaning of a record.
- One-cent drift in price, changed recipient, or changed description: canonical digest must change.
- An amount above a hypothetical $30 project ceiling: can still be represented as a proposal but must never be interpreted as approved spending.
- An ambiguous, unsigned or synthetic source: the hash only identifies *what bytes were supplied*. It does not authenticate the sender or prove payment.

## What passes and what remains unproven

The test suite covers **record validation, proposal integrity and fail-closed parsing**, not real authorization, one-use permits, transaction durability, independent custody or consequence verification. A digest is not a signature. A recommendation is not a payment. An absence of an outgoing API in this toy example does not establish Pulpo runtime isolation.

## Extension labs

Read SQLite chapter 16 and implement *offline, temporary-file* append and restart tests. Then compare a read-only calculation process with an actor capable of changing a real database file: the key difference is not Python syntax, but privileged capability custody.

When ready, use the canonical independently reviewed Pulpo code/tests and real isolated service roles rather than growing this exercise into a duplicate authority system.
