# Quickstart

Proof Wallet is experimental software. Since, like the Glacier Protocol, it is to be executed on an airgapped laptop running Ubuntu, this quickstart assumes a fresh Ubuntu install. You can test the wallet out by booting Ubuntu from a thumbdrive or by running it in VirtualBox.

## Prepare Software Dependencies
Run the following commands in Terminal to setup your environment.

### Update Ubuntu
```
sudo add-apt-repository universe
sudo apt-get update
```

### Install Bitcoin v0.20.1 or higher
_Download bitcoin v0.20.1 source and signatures_
```
wget https://bitcoin.org/bin/bitcoin-core-0.20.1/bitcoin-0.20.1-x86_64-linux-gnu.tar.gz
wget https://bitcoin.org/bin/bitcoin-core-0.20.1/SHA256SUMS.ascx
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

_Check that the downloaded binary matches the SHA256SUMS file_
```
sha256sum -c --ignore-missing SHA256SUMS.asc
```

_You should see the following..._
```
bitcoin-0.20.1-x86_64-linux-gnu.tar.gz: OK
sha256sum: WARNING: 20 lines are improperly formatted
```

_Extract the binaries and copy them to the local binary directory_
```
tar xf bitcoin-0.20.1-x86_64-linux-gnu.tar.gz
sudo cp bitcoin-0.20.1/bin/bitcoin-cli /usr/local/bin/
sudo cp bitcoin-0.20.1/bin/bitcoind /usr/local/bin/
```

### Install QR code dependencies
```
sudo apt-get install qrencode zbar-tools -y
```

### Download Proof Wallet
```
git clone https://github.com/hodlwave/proof-wallet.git
cd proof-wallet
git submodule update --init
./proofwallet --help
```

_Ensure you see the following..._
```
usage: proofwallet.py [-h] [-v]
                      {entropy,create-wallet,view-addresses,sign-psbt} ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity

Subcommands:
  {entropy,create-wallet,view-addresses,sign-psbt}
    entropy             Generate computer entropy
    create-wallet       Create a BIP39 HD wallet
    view-addresses      View deposit addresses
    sign-psbt           Sign a PSBT

For more help, include a subcommand, e.g. `./proofwallet.py entropy --help`
```
You have now installed all the software you need to demo Proof Wallet. See [usage](../doc/usage.md) for documentation on how to use it.

