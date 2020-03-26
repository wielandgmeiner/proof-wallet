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
| `view-addresses.no-matching-xpub.run`        | Fail when no xpub matches the mnemonic's xpub |

## Tests for withdrawls (`sign-psbt`)

| Test case                 | Coverage goal |
| --------------------------| ------------- |
| `sign-psbt.run`        | Basic flow; sign a psbt with 1 change address |
| `sign-psbt.no-matching-xpub.run`        | Fail when no xpub matches the mnemonic's xpub |
| `sign-psbt.non-witness-input.run`        | Fail when the Tx contains a non-witness input |
| `sign-psbt.no-bip32-input-meta.run`        | Fail when an input doesn't have bip32 metadata |
| `sign-psbt.wrong-bip32-input-meta-fps.run`        | Fail when an input'S bip32 metadata fingerprints don't match ours |
| `sign-psbt.wrong-input-scriptPubKey-type.run`        | Fail when an input's scriptPubKey type isn't correct |
| `sign-psbt.no-input-witness-script.run`        | Fail when an input doesn't contain a witness script |
| `sign-psbt.input-witness-script-hash-no-match.run`        | Fail when the hash of an input's witness script doesn't match the witness_utxo's scriptPubKey |
| `sign-psbt.input-different-bip32-paths.run`        | Fail when there are multiple bip32 derivation paths for one input |
| `sign-psbt.input-unsupported-bip32-path.run`        | Fail when an input's bip32 path is not supported  |
| `sign-psbt.input-unexpected-derived-address.run`        | Fail when the input address derived from the bip32 paths doesn't match the witness_utxo's scriptPubKey |
| `sign-psbt.input-unsupported-sighash.run`        | Fail when an input specifies a sighash type that is not 'ALL' |
| `sign-psbt.output-different-bip32-paths.run`        | Fail when there are multiple bip32 derivation paths for one change output |
| `sign-psbt.output-unsupported-bip32-path.run`        | Fail when a change output's bip32 path is not supported |
| `sign-psbt.output-unexpected-derived-address.run`        | Fail when a change output address derived from the bip32 paths doesn't match the Tx vout scriptPubKey |
| `sign-psbt.output-no-witness-script.run`        | Fail when a change output doesn't contain a witness script |
| `sign-psbt.output-witness-script-hash-no-match.run`        | Fail when the hash of a change output's witness script doesn't match the Tx output's scriptPubKey |
| `sign-psbt.external-change-output.run`        | Display a warning when a psbt spends bitcoins to an external wallet address as change |
| `sign-psbt.no-change-outputs.run`        | Display a warning when there are no identifiable change outputs in the psbt |

## Tests for other miscellaneous

| Filename | Coverage goal |
| -------- | ------------- |
| `entropy.run` | Entropy subcommand |
| `safety-check-fails.run` | Failed safety checks |
