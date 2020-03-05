# Proof Wallet

# Overview
Proof Wallet is a fork of Glacier Protocol that adds BIP39, BIP174 (aka PSBT), Hierarchical Deterministic multisignature wallets, and enables key generation and sequential signing of transactions on separate airgapped computers.

Under the hood, Proof Wallet uses Bitcoin Core's descriptor wallet functionality. In line with the Glacier Protocol design principles, Proof Wallet is a minimal wallet that enables secure private key generation, address verification, and transaction signing. The wallet is limited to generating outputs that match the following descriptor:

```
wsh(sortedmulti(M, [xfp_1]xpub_1/change/idx, [xfp_2]xpub_2/change/idx, ... , [xfp_n]xpub_n/change/idx))
```

That is, Proof Wallet consists of native segwit multisignature (M of N) outputs that adhere to BIP67 where the public keys derive from N xpubs with the same change (either 0 or 1) and index values.

# Quickstart
Proof Wallet is still experimental software. Those wishing to test it out must build Bitcoin Core from source to utilize the yet-unreleased `sortedmulti` descriptor function that Proof Wallet depends on; once Bitcoin Core v0.20 is realeased, users will be able to use the signed binaries available on bitcoin.org.

As Glacier Protocol is executed on an airgapped laptop running Ubuntu, this Quickstart assumes a fresh Ubuntu 18.04 install. You can test the wallet out by booting the distro off of a USB or using Virtual Machine software such as VirtualBox.

## Setup
Run the following commands in Terminal to setup your environment.

_Build Bitcoin Core from source_
```
sudo add-apt-repository universe
sudo apt-get update

# build requirements
sudo apt-get install git build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 -y

# dependencies
sudo apt-get install libevent-dev libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-test-dev libboost-thread-dev -y

# download bitcoin
cd /home/ubuntu
git clone https://github.com/bitcoin/bitcoin.git
cd /home/ubuntu/bitcoin

# BerkeleyDB
./contrib/install_db4.sh `pwd`

# Build
./autogen.sh
export BDB_PREFIX='/home/ubuntu/bitcoin/db4'
./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include"
make
```

_Install QR code dependencies_
```
sudo apt-get install qrencode zbar-tools
```

_Download Proof Wallet_
```
cd /home/ubuntu
git clone https://github.com/hodlwave/proof-wallet.git
cd /home/ubuntu/proof-wallet
git checkout proof-wallet
```

## Wallet Programs
```
python3 glacierscript.py entropy
```
Generate 64 hex characters of entropy from /dev/random used as additive entropy during the `create-wallet` program

```
python3 glacierscript.py create-wallet
```

Prompt the user for at least 100 dice rolls and the hex characters generated in the `entropy` step. The programs outputs a 24 words BIP39 mnemonic phrase and xpub to the console; it also saves a copy of the xpub as a QR code image in the wallet directory.

```
glacierscript.py view-addresses -m [M] -n [N]
```

Prompts the user to enter the BIP39 mnemonic phrase and N xpubs in the terminal. Afterwards 10 wallet addresses are displayed at a time, starting from `m/0/0` to `m/0/9`. By entering `NEXT`, `PREV`, and `CHANGE` in the terminal, the user can browse the rest of the addresses in the wallet.

```
glacierscript.py sign-psbt -m [M] -n [N]
```
Prompts the user to enter the BIP39 mnemonic phrase and N xpubs in the terminal. The the user must enter a base64 encoded psbt to sign. If the psbt passes the stringent validations, a summary of the transaction is output to the console. The user can analyze the transaction and optionally `SIGN` it or `EXIT` the program. If the user chooses to sign it, Proof Wallet outputs the updated psbt to the terminal and QR code(s) with the signed psbt data are save in the wallet directory.
