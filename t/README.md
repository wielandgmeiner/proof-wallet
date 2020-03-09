_All credit for developing this test suite goes to @bitcoinhodler_
# Testing Proof Wallet

This directory contains tests for the developers of Proof Wallet to
ensure high quality and backward compatibility.

# Running Tests

## Running all tests
```
$ make
```

## Running one test
```
$ make t/create-wallet.test
```
Note there is no actual file by that name.

## Measuring code coverage
```
$ make COVERAGE=1; firefox coverage-report/index.html
```

# Writing Tests

1. Create a `t/foo.run` bash script; make sure it is `chmod +x`.

2. Create a matching `t/foo.golden` file; `touch t/foo.golden` is
   sufficient to start

3. Run the test using `make t/foo.test`; it will fail since it doesn't
   match golden

4. Manually check `t/foo.out` to ensure desired output

5. `mv t/foo.{out,golden}`

6. Ensure test passes now

7. Commit!


# Test Catalog

## Tests for `create-wallet`

| Filename | Coverage goal |
| -------- | ------------- |
| `create-wallet.run` | Basic flow |
| `create-wallet.input-checks.run` | Input validation |

## Tests for deposits (`view-addresses`)
| Test case                 | Coverage goal |
| --------------------------|  ------------- |
| `view-addresses.run`        | Basic flow; use all available commands to explore addresses |
| `view-addresses.trust-xpubs.run`        | Basic flow for viewing addresses with only the xpubs |
| `view-addresses.mnemonic-too-short.run`        | Fail when mnemonic isn't 24 words long |
| `view-addresses.mnemonic-invalid.run`        | Fail when mnemonic is invalid |
| `view-addresses.xpub-invalid-for-network.run`        | Fail when a cosigner xpub is invalid for the specified network |
| `view-addresses.xpub-invalid.run`        | Fail when a cosigner xpub is invalid |
| `view-addresses.duplicate-xpubs.run`        | Fail when the user enters duplicate xpubs |

## Tests for withdrawls (`sign-psbt`)

| Test case                 | Coverage goal |
| --------------------------| ------------- |
| `sign-psbt.run`        | Basic flow; sign a psbt with 1 change address |

## Tests for other miscellaneous

| Filename | Coverage goal |
| -------- | ------------- |
| `entropy.run` | Entropy subcommand |
| `safety-check-fails.run` | Failed safety checks |
