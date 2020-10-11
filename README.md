# Proof Wallet

## Overview
Proof Wallet is a project that attempts to improve various limitations of the Glacier Protocol without compromising on its security assumptions. Some improvements over Glacier Protocol include the following:
* BIP39 mnemonic phrases for private key data backup.
* BIP32 HD wallet support so users can create a single private key (for each cosigner) to manage alladdresses in their multisig wallet.
* BIP174; aka Partially Signed Bitcoin Transactions, PSBTs allow Proof Wallet to seamlessly interoperate with multisig coordinators like [Specter Desktop](https://github.com/cryptoadvance/specter-desktop) and [Fully Noded 2](https://github.com/BlockchainCommons/FullyNoded-2) as well as other offline wallets like [Coldcard](https://github.com/Coldcard/firmware), [Specter-DIY](https://github.com/cryptoadvance/specter-diy), [Electrum](https://github.com/spesmilo/electrum), etc.
* Sequential signing: unlike the Glacier Protocol, users can take full advantage of multisig security by generating private keys and signing transactions _separately_ and _independently_ of other cosigners in the multisig quorum.

Proof Wallet is an ultra-minimalist wallet, which relies on Bitcoin Core for as much computation as possible. In line with the Glacier Protocol design principles, Proof Wallet supports secure private key generation, address verification, and transaction signing.

## Additional Information
* [Quickstart](doc/quickstart.md) walks through installing Proof Wallet's dependencies so users can demo its functionality
* [Usage](doc/usage.md) explains the various Proof Wallet commands
* [Roadmap](doc/roadmap.md) tracks the state of the project and future plans
