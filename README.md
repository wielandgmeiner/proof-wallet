# Proof Wallet

# Overview
Proof Wallet is a fork of Glacier Protocol that adds BIP39, BIP174 (aka PSBT), Hierarchical Deterministic multisignature wallets, and enables key generation and sequential signing of transactions on separate airgapped computers.

Under the hood, Proof Wallet uses Bitcoin Core's descriptor wallet functionality. In line with the Glacier Protocol design principles, Proof Wallet is a minimal wallet that enables secure private key generation, address verification, and transaction signing. The wallet is limited to generating outputs that match the following descriptor:

```
wsh(sortedmulti(M, [xfp_1]xpub_1/change/idx, [xfp_2]xpub_2/change/idx, ... , [xfp_n]xpub_n/change/idx))
```

That is, Proof Wallet consists of native segwit multisignature (M of N) outputs that adhere to BIP67 where the public keys derive from N xpubs with the same change (either 0 or 1) and index values.

# Quickstart
Proof Wallet is still experimental software. The code relies on the `sortedmulti` descriptor, which will be supported starting with Bitcoin Core's v0.20 release; meanwhile, you can test by using the v0.20 release candidate 1 binary located [here](https://bitcoin.org/bin/bitcoin-core-0.20.0/test.rc1/).

As Glacier Protocol is executed on an airgapped laptop running Ubuntu, this Quickstart assumes a fresh Ubuntu 18.04 install. You can test the wallet out by booting the distro off of a USB or using Virtual Machine software such as VirtualBox.

## Setup
Run the following commands in Terminal to setup your environment.

### Update Ubuntu
```
sudo add-apt-repository universe
sudo apt-get update
```

### Install Bitcoin v0.20-rc1 source
_Download bitcoin v0.20-rc1 source and signatures_
```
wget https://bitcoin.org/bin/bitcoin-core-0.20.0/test.rc1/bitcoin-0.20.0rc1-x86_64-linux-gnu.tar.gz
wget https://bitcoin.org/bin/bitcoin-core-0.20.0/test.rc1/SHA256SUMS.asc
```

_Download Wladimir's public key and verify signatures_
```
wget https://bitcoin.org/laanwj-releases.asc
gpg --import laanwj-releases.asc
gpg --verify SHA256SUMS.asc
```

_Ensure you see the following..._
```
Good signature from "Wladimir J. van der Laan (Bitcoin
Core binary release signing key) <laanwj@gmail.com>"

Ignore this: WARNING: This key is not certified with a trusted
signature! There is no indication that the signature belongs to the
owner.

Ensure primary key fingerprint is: 01EA 5486 DE18 A882 D4C2  6845 90C8 019E 36C2 E964
```

_Extract the binaries and copy them to the local binary directory_
```
tar xf bitcoin-0.20.0rc1-x86_64-linux-gnu.tar.gz
sudo cp bitcoin-0.20.0rc1/bin/bitcoin-cli /usr/local/bin/
sudo cp bitcoin-0.20.0rc1/bin/bitcoind /usr/local/bin/
```

### Install QR code dependencies
```
sudo apt-get install qrencode zbar-tools -y
```

### Download Proof Wallet
```
git clone https://github.com/hodlwave/proof-wallet.git
cd proof-wallet
```

## Wallet Programs
```
./glacierscript.py entropy
```
Generate 64 hex characters of entropy from /dev/random used as additive entropy during the `create-wallet` program

```
./glacierscript.py create-wallet [--testnet|--regtest]
```

Prompt the user for at least 100 dice rolls and the hex characters generated in the `entropy` step. The programs outputs a 24 words BIP39 mnemonic phrase and xpub to the console; it also saves a copy of the xpub as a QR code image in the wallet directory.

```
./glacierscript.py view-addresses -m [M] -n [N] [--testnet|--regtest]
```

Prompts the user to enter the BIP39 mnemonic phrase and N xpubs in the terminal. Afterwards 10 wallet addresses are displayed at a time, starting from `m/0/0` to `m/0/9`. By entering `NEXT`, `PREV`, and `CHANGE` in the terminal, the user can browse the rest of the addresses in the wallet.

```
./glacierscript.py sign-psbt -m [M] -n [N] [--testnet|--regtest]
```
Prompts the user to enter the BIP39 mnemonic phrase and N xpubs in the terminal. The the user must enter a base64 encoded psbt to sign. If the psbt passes the stringent validations, a summary of the transaction is output to the console. The user can analyze the transaction and optionally `SIGN` it or `EXIT` the program. If the user chooses to sign it, Proof Wallet outputs the updated psbt to the terminal and QR code(s) with the signed psbt data are save in the wallet directory.
