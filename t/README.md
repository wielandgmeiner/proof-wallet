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

## Tests for importing BIP39 mnemonic
| Test case                 | Coverage goal |
| --------------------------|  ------------- |
| `mnemonic-length-24-happy.run`        | Import 24 word mnemonic successfully |
| `mnemonic-length-12-happy.run`        | Import 12 word mnemonic successfully |
| `mnemonic-unsupported-length.run`        | Fail when mnemonic isn't 12 or 24 words long |
| `mnemonic-invalid.run`        | Fail when mnemonic is invalid |

## Tests for importing descriptor keys
| Test case                 | Coverage goal |
| --------------------------|  ------------- |
| `descriptor-valid.run`        | Import various valid output descriptors successfully |
| `descriptor-invalid-fingerprint-length.run`        | Fail when fingerprint is incorrect length |
| `descriptor-invalid-fingerprint-chars.run`        | Fail when fingerprint contains non-hex characters |
| `descriptor-missing-fingerprint.run`        | Fail when no fingerprint is present |
| `descriptor-no-xpub.run`        | Fail when no xpub is present |
| `descriptor-path-invalid-char.run`        | Fail when the path contains invalid characters |
| `descriptor-path-leading-zeros.run`        | Fail when any path index contains leading zeros |
| `descriptor-xpub-invalid.run`        | Fail when xpub is invalid |
| `descriptor-duplicate-fingerprints.run`        | Fail when importing the same fingerprint more than once |
| `descriptor-duplicate-xpubs.run`        | Fail when importing the same xpub more than once |

## Tests for deposits (`view-addresses`)
| Test case                 | Coverage goal |
| --------------------------|  ------------- |
| `view-addresses.run`        | Basic flow; use all available commands to explore addresses |
| `view-addresses.trust-xpubs.run`        | Basic flow for viewing addresses with only the xpubs |
| `view-addresses.no-matching-xpub.run`        | Fail when no xpub matches the mnemonic's xpub |

## TODO: Tests for withdrawls (`sign-psbt`)

| Todo | Test case                 | Coverage goal |
|-----| --------------------------| ------------- |
| yes | `sign-psbt.run`        | Basic flow; sign a psbt with 1 change address |
| no | `sign-psbt.no-matching-xpub.run`        | Fail when no xpub matches the mnemonic's xpub |
| no | `sign-psbt.invalid-psbt.run`        | Fail when psbt is invalid |
| no | `sign-psbt.input-non-witness-utxo-missing.run`        | Fail when `PSBT_IN_NON_WITNESS_UTXO` is missing  |
| no | `sign-psbt.input-witness-utxo-missing.run`        | Fail when `PSBT_IN_NON_WITNESS_UTXO` is missing  |
| no | `sign-psbt.input-bip32-metadata-missing.run`        | Fail when `PSBT_IN_BIP32_DERIVATION` is missing |
| no | `sign-psbt.input-bip32-metadata-wrong.run`        | Fail when `PSBT_IN_BIP32_DERIVATION` fingerprints don't match ours |
| no | `sign-psbt.input-bip32-metadata-extra.run`        | Fail when `PSBT_IN_BIP32_DERIVATION` contains an extra fingerprint |
| no | `sign-psbt.input-scriptPubKey-type-wrong.run`        | Fail when an input's scriptPubKey type isn't correct |
| no | `sign-psbt.input-witness-script-missing.run`        | Fail when `PSBT_IN_WITNESS_SCRIPT` is missing |
| no | `sign-psbt.input-witness-script-hash-no-match.run`        | Fail when the SHA256 of `PSBT_IN_WITNESS_SCRIPT` doesn't match the `PSBT_IN_WITNESS_UTXO` scriptPubKey |
| no | `sign-psbt.input-bip32-paths-dont-match.run`        | Fail when at least 1 `PSBT_IN_BIP32_DERIVATION` path (hardened) doesn't match ours |
| no | `sign-psbt.input-different-unhardened-paths.run`        | Fail when at least 1 `PSBT_IN_BIP32_DERIVATION` path (unhardened) doesn't match ours |
| no | `sign-psbt.input-unsupported-bip32-path.run`        | Fail when an input's bip32 path (unhardened part) is not supported |
| no | `sign-psbt.input-unexpected-derived-address.run`        | Fail when the input address derived from the bip32 paths doesn't match the witness_utxo's scriptPubKey |
| no | `sign-psbt.input-unsupported-sighash.run`        | Fail when an input specifies a sighash type that is not 'ALL' |
| yes | `sign-psbt.output-different-bip32-paths.run`        | Fail when there are multiple bip32 derivation paths for one change output |
| yes | `sign-psbt.output-unsupported-bip32-path.run`        | Fail when a change output's bip32 path is not supported |
| no | `sign-psbt.output-unexpected-derived-address.run`        | Fail when a change output address derived from the bip32 paths doesn't match the Tx's scriptPubKey |
| no | `sign-psbt.output-witness-script-missing.run`        | Fail when `PSBT_OUT_WITNESS_SCRIPT` is missing |
| no | `sign-psbt.output-witness-script-hash-no-match.run`        | Fail when the hash of a change output's witness script doesn't match the Tx output's scriptPubKey |
| no | `sign-psbt.no-change-outputs.run`        | Display a warning when there are no identifiable change outputs in the psbt |

## Tests for other miscellaneous

| Filename | Coverage goal |
| -------- | ------------- |
| `entropy.run` | Entropy subcommand |
| `safety-check-fails.run` | Failed safety checks |
