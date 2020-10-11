# Usage

Running the help command shows that Proof-Wallet includes 4 wallet programs:

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

Let us walk through an example to understand each program's purpose within the greater wallet. For this example, we will create a 2/3 multisig wallet on testnet with Proof Wallet as 1 cosigner.

## Entropy

First, let us ask our computer for 256 bits of entropy.
```
./proofwallet.py entropy
```

Notice that Proof Wallet always walks you through several safety checks before proceeding to security critical operations. If you are just testing Proof Wallet on testnet or regtest, feel free to ignore the safety checks, but __ALWAYS__ use them when handling real funds on mainnet.

```
Are you running this on a computer WITHOUT a network connection of any kind? (y/n)?y
Have the wireless cards in this computer been physically removed? (y/n)?y
Are you running on battery power? (y/n)?y
Are you running on an operating system booted from a USB drive? (y/n)?y
Is your screen hidden from view of windows, cameras, and other people? (y/n)?y
Are smartphones and all other nearby devices turned off and in a Faraday bag? (y/n)?y
```

Finally, we get the entropy that we requested:
```
Making a random data string....
(If the string doesn't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.)

Computer entropy: af37 f884 66b8 806c c368 960d c06d 1749 baa7 012a 26ed cfef 1af4 2e62 ce5e 1f3
```

Copy and paste the 32 bytes of entropy (in this example  `af37 f884 66b8 806c c368 960d c06d 1749 baa7 012a 26ed cfef 1af4 2e62 ce5e 1f3` but your entropy will always be different) into a text editor as we will need it in the next step.


## Create Wallet
With the entropy from the previous step, we can now create our HD wallet. The output of this step includes two things:
1. a BIP39 mnemonic phrase (i.e. our cosigner's private key data)
2. the public output descriptor we will share with our preferred multisig coordinator software.

```
./proofwallet.py create-wallet --testnet
```

Proof Wallet asks us to enter the results of at least 100 dice rolls and the entropy from the previous step.
```
(safety checks omitted for brevity)

Creating cold storage private key data.

Enter 100 dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:
65555 63423 62534 54622 64112 16621 11213 46226 65526 11151 55241 26352 45436 21312 36211 23326 56363 66146 14461 35431
Enter at least 64 characters of computer entropy. Spaces are OK, and will be ignored:
af37 f884 66b8 806c c368 960d c06d 1749 baa7 012a 26ed cfef 1af4 2e62 ce5e 1f30
```

The Proof Wallet software mixes these two entropy sources and generates our private and public key data. Note that similar to the Glacier Protocol, we could check that our machine isn't compromising private key generation by reproducing the steps with the same inputs on a separate device. In both cases, we should get the following output:

```
BIP39 Mnemonic Phrase: 
1. venue
2. close
3. echo
4. weird
5. luxury
6. quick
7. surprise
8. people
9. great
10. coyote
11. blossom
12. marble
13. sorry
14. honey
15. couple
16. icon
17. apart
18. kite
19. search
20. struggle
21. mind
22. shoulder
23. spin
24. cannon

public key metadata:
[0e529b86]tpubD6NzVbkrYhZ4YLWEAb9aUnUKuBWuxrSqoCXesa5ihfoM1yvTBYMBJHBgAjY5qXBTtMyAuQraQQjP1h5tqpSkWqxAk97GcjbgKsvtujCXUqi

QR code for public-key-metadata written to public-key-metadata.png
```

Now you can transfer the public key metadata (`[0e529b86]tpubD6NzVbkrYhZ4YLWEAb9aUnUKuBWuxrSqoCXesa5ihfoM1yvTBYMBJHBgAjY5qXBTtMyAuQraQQjP1h5tqpSkWqxAk97GcjbgKsvtujCXUqi`) to your online multisig coordinator applicaation of choice by scanning the QR code written to `/path/to/proof-wallet/public-key-metadata.png`.

# View Addresses
In order to securely receive bitcoins to a multisig wallet, it is imperative that you verify the receive address on at least M offline signers. When setting up the multisig wallet initially, you must verify the first address on all N offline signers to ensure that they are all in agreement with each other.

A pre-requisite to this step is to transfer the wallet's cosigner public output descriptors to the airgapped machine that Proof Wallet is running on. You can do this with the `zbarcam` program you downloaded.
```
zbarcam --raw
<QR code data will appear below as you scan them>
[41f408e8/1']tpubD8kF7X4sjY6y5zRgmYhjd4878gYVtuesSxo8zhYkNdb5KRZK7tU42yS2RTBA6Mn86VRfRXk6RqJ6FQ35tDaLxyhEGG2SSKAf1ifcYG9fNjX
[2eb4fc90/48'/1'/0'/2']tpubDFFFhev78PB1E9LUcWoeBrwJUQrhH23f2ShmW4DueA6WDkd27qgyJeWNL62FcNQHbh6wAJhGhYm2g3xQidQ6G2SpNBh8qon3HLhc6vYzyJy
```

Finally we can view our wallet addresses, including our first receive address (`tb1qzaa0aawpkemt98j52svmfau2q20fn5jfc6vr7cgm5anxa9qy7clqxfjz35`).
```
./proofwallet.py view-addresses -m 2 -n 3 --testnet

(safety checks omitted for brevity)

Enter your BIP39 mnemonic phrase (separate the words with whitespace): venue close echo weird luxury quick surprise people great coyote blossom marble sorry honey couple icon apart kite search struggle mind shoulder spin cannon

Input 3 valid descriptor keys

Enter descriptor key #1: [0e529b86]tpubD6NzVbkrYhZ4YLWEAb9aUnUKuBWuxrSqoCXesa5ihfoM1yvTBYMBJHBgAjY5qXBTtMyAuQraQQjP1h5tqpSkWqxAk97GcjbgKsvtujCXUqi

Enter descriptor key #2: [41f408e8/1']tpubD8kF7X4sjY6y5zRgmYhjd4878gYVtuesSxo8zhYkNdb5KRZK7tU42yS2RTBA6Mn86VRfRXk6RqJ6FQ35tDaLxyhEGG2SSKAf1ifcYG9fNjX

Enter descriptor key #3: [2eb4fc90/48'/1'/0'/2']tpubDFFFhev78PB1E9LUcWoeBrwJUQrhH23f2ShmW4DueA6WDkd27qgyJeWNL62FcNQHbh6wAJhGhYm2g3xQidQ6G2SpNBh8qon3HLhc6vYzyJy
================================================================================
Derivation Path, Address
../0/0, tb1qzaa0aawpkemt98j52svmfau2q20fn5jfc6vr7cgm5anxa9qy7clqxfjz35 (Enter 0 to save as a QR code in address.png)
../0/1, tb1qcu8w7ajasvy7wzwm642u0z2la98te6pzj8jy5kp09qpp94nz44fqnavd8e (Enter 1 to save as a QR code in address.png)
../0/2, tb1q5c0ajawhv6ckjgnpqthpne5mmetfz43sh237end8w75wedc6nq3ssupug2 (Enter 2 to save as a QR code in address.png)
../0/3, tb1qvu8pjse92qlwyyx4w0324w8jcrccw9cyvu33m7r4snlfvthvdq6qe0akfl (Enter 3 to save as a QR code in address.png)
../0/4, tb1qfvavkxn0ezzcqh6pse0cn370j8thknma82uqk0rwceffjvfap0rqxhntkw (Enter 4 to save as a QR code in address.png)
../0/5, tb1qtk0vmgx2wern265tv39e5g8rhamck8gnu23wwde4vah0a80rce8qn9gsst (Enter 5 to save as a QR code in address.png)
../0/6, tb1qxx254ssgrvtedrqfp0ysd2hvyhfny86h3kka6epycsh9y9g7pt7s3mr9sf (Enter 6 to save as a QR code in address.png)
../0/7, tb1q74j27e4hgzyzzqysyaqupdgehhykl4gg7qak9zy5002nr66n4k7s2t8l8t (Enter 7 to save as a QR code in address.png)
../0/8, tb1q25gm47mzp5mntxd7hdslw6ur59krysls6ak608j57wuufzf0mqhqsf2mul (Enter 8 to save as a QR code in address.png)
../0/9, tb1qnlsx9kl062ehcq755xythd8n2qcqpaf82dtcga8x0z4vhfqsx39q3p8e78 (Enter 9 to save as a QR code in address.png)

Controls:
    'NEXT' -- view next 10 addresses
    'PREV' -- view previous 10 addresses
    'CHANGE' -- toggle to/from change addresses
    'QUIT' -- quit proof wallet

Enter your desired command:
```

Note that Proof Wallet displays 10 wallet addresses simultaneously. By entering `NEXT`, `PREV`, and `CHANGE` into the terminal, you can explore your other addresses.

# Sign PSBT
You've received 100,000 sats to our first address from a testnet faucet so now let's send some of it back to the faucet. After you generate a PSBT with your multisig coordinator, use `zbarcam` to transfer the base64 encoded PSBT to your airgapped laptop. During the signing flow, you will again be prompted for your BIP39 mnemonic phrase and all N public output descriptors; however, this time, you will also be prompted to enter the base64 encoded psbt.

```
./proofwallet.py sign-psbt -m 2 -n 3 --testnet

(safety checks omitted for brevity)

Enter your BIP39 mnemonic phrase (separate the words with whitespace): venue close echo weird luxury quick surprise people great coyote blossom marble sorry honey couple icon apart kite search struggle mind shoulder spin cannon

Input 3 valid descriptor keys

Enter descriptor key #1: [0e529b86]tpubD6NzVbkrYhZ4YLWEAb9aUnUKuBWuxrSqoCXesa5ihfoM1yvTBYMBJHBgAjY5qXBTtMyAuQraQQjP1h5tqpSkWqxAk97GcjbgKsvtujCXUqi

Enter descriptor key #2: [41f408e8/1']tpubD8kF7X4sjY6y5zRgmYhjd4878gYVtuesSxo8zhYkNdb5KRZK7tU42yS2RTBA6Mn86VRfRXk6RqJ6FQ35tDaLxyhEGG2SSKAf1ifcYG9fNjX

Enter descriptor key #3: [2eb4fc90/48'/1'/0'/2']tpubDFFFhev78PB1E9LUcWoeBrwJUQrhH23f2ShmW4DueA6WDkd27qgyJeWNL62FcNQHbh6wAJhGhYm2g3xQidQ6G2SpNBh8qon3HLhc6vYzyJy

Enter the psbt for the transaction you wish to sign: cHNidP8BAIACAAAAAX6yqlXfq2noZGMq8iHdTHFJ+NrS2qogj+oPF1yp0nKnAAAAAAD+////Ag4BAQAAAAAAIgAgGL1cIBV0qyL+8w4UXa2bdr8o05cXwNhYWMim3rrBXEvQhAAAAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAABAJQCAAAAAUiVotroztz0eRlYx6Da/e2ziay2vwzY4gBrnx8wsxx+AAAAABcWABTu0/myMnoFT+ujZi5D4CtegF1zeP7///8CoIYBAAAAAAAiACAXev71wbZ2sp5UVBm094oCnpnSScaYP2Ebp2ZulAT2Pi3BSgAAAAAAFgAU/XhNXLSbpDq3o+MioSS2htBDQBleaBwAAQEroIYBAAAAAAAiACAXev71wbZ2sp5UVBm094oCnpnSScaYP2Ebp2ZulAT2PgEFaVIhA4MSrPvDrbjE/vDvvIqU1+KtmzF8vbUSYes5jIinPbSEIQORahX4UEjoM55zl+aQv3PEsaOj1nYbDVXVgG5JikwFeyEDnW2ef/uER6S/jth6HllbiWdootpHgHNYHFsWYc99Wc5TriIGA4MSrPvDrbjE/vDvvIqU1+KtmzF8vbUSYes5jIinPbSEDA5Sm4YAAAAAAAAAACIGA5FqFfhQSOgznnOX5pC/c8Sxo6PWdhsNVdWAbkmKTAV7EEH0COgBAACAAAAAAAAAAAAiBgOdbZ5/+4RHpL+O2HoeWVuJZ2ii2keAc1gcWxZhz31ZzhwutPyQMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAAAEBaVIhAoSfrRv5vacqRmgb8V5WMRbdCk1MCcVhVZIkD9BjLUokIQKc6QP3DptqS898pRwnvkN8Unt8qr1HUhoHLIbOlTJAMyEDaBjHa0cvvMCvCZCeg2W4Rn1tHhAlTG3xtcgB6wLq+FlTriICAoSfrRv5vacqRmgb8V5WMRbdCk1MCcVhVZIkD9BjLUokHC60/JAwAACAAQAAgAAAAIACAACAAQAAAAAAAAAiAgKc6QP3DptqS898pRwnvkN8Unt8qr1HUhoHLIbOlTJAMxBB9AjoAQAAgAEAAAAAAAAAIgIDaBjHa0cvvMCvCZCeg2W4Rn1tHhAlTG3xtcgB6wLq+FkMDlKbhgEAAAAAAAAAAAA=
```
At this point, Proof Wallet will perform several validations on the input data to ensure that this transaction is safe to sign. If all of the validations succeed, a summary of the transaction is printed to the console for you to evaluate. Then simply enter `SIGN` (or `QUIT` to abort). Assuming you sign the transaction, Proof Wallet prints the base64 encoded signed psbt to the terminal as well as the locations of QR codes, which contain this data.

```
Validating the PSBT...
================================================================================
PSBT validation was successful.

+-----------------------+
|                       |
|  Transaction Summary  |
|                       |
+-----------------------+
Transaction ID: 475d3e2a8d8f90e41aa2e9c84a587f0bf5b5ac8be7d5009ae749ea00e1e8c79e
Virtual size: 192 vbyte
Fee (total): 0.00000194
Fee (rate): 1.0 sat/byte

Inputs (1)
a772d2a95c...df55aab27e:0	tb1qzaa0aawpkemt98j52svmfau2q20fn5jfc6vr7cgm5anxa9qy7clqxfjz35	0.00100000

Outputs (2)
[CHANGE] tb1qrz74cgq4wj4j9lhnpc29mtvmw6lj35uhzlqdskzcezndawkpt39sfjvck2	0.00065806
[NOT CHANGE] mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt	0.00034000

Controls:
    'SIGN' -- sign the transaction
    'QUIT' -- quit proof wallet without signing the transaction

Enter your desired command: SIGN

Signed psbt (base64):
cHNidP8BAIACAAAAAX6yqlXfq2noZGMq8iHdTHFJ+NrS2qogj+oPF1yp0nKnAAAAAAD+////Ag4BAQAAAAAAIgAgGL1cIBV0qyL+8w4UXa2bdr8o05cXwNhYWMim3rrBXEvQhAAAAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAABAJQCAAAAAUiVotroztz0eRlYx6Da/e2ziay2vwzY4gBrnx8wsxx+AAAAABcWABTu0/myMnoFT+ujZi5D4CtegF1zeP7///8CoIYBAAAAAAAiACAXev71wbZ2sp5UVBm094oCnpnSScaYP2Ebp2ZulAT2Pi3BSgAAAAAAFgAU/XhNXLSbpDq3o+MioSS2htBDQBleaBwAAQEroIYBAAAAAAAiACAXev71wbZ2sp5UVBm094oCnpnSScaYP2Ebp2ZulAT2PiICA4MSrPvDrbjE/vDvvIqU1+KtmzF8vbUSYes5jIinPbSERzBEAiBTthueNzZ5kaP5sLanVeKnjCqME0YXPM6eFYIbimeUFQIgXniPsvIm6X7z5iBHF70S7SZhp1itUkknpNcxoN4fJmYBAQVpUiEDgxKs+8OtuMT+8O+8ipTX4q2bMXy9tRJh6zmMiKc9tIQhA5FqFfhQSOgznnOX5pC/c8Sxo6PWdhsNVdWAbkmKTAV7IQOdbZ5/+4RHpL+O2HoeWVuJZ2ii2keAc1gcWxZhz31ZzlOuIgYDgxKs+8OtuMT+8O+8ipTX4q2bMXy9tRJh6zmMiKc9tIQMDlKbhgAAAAAAAAAAIgYDkWoV+FBI6DOec5fmkL9zxLGjo9Z2Gw1V1YBuSYpMBXsQQfQI6AEAAIAAAAAAAAAAACIGA51tnn/7hEekv47Yeh5ZW4lnaKLaR4BzWBxbFmHPfVnOHC60/JAwAACAAQAAgAAAAIACAACAAAAAAAAAAAAAAQFpUiEChJ+tG/m9pypGaBvxXlYxFt0KTUwJxWFVkiQP0GMtSiQhApzpA/cOm2pLz3ylHCe+Q3xSe3yqvUdSGgcshs6VMkAzIQNoGMdrRy+8wK8JkJ6DZbhGfW0eECVMbfG1yAHrAur4WVOuIgIChJ+tG/m9pypGaBvxXlYxFt0KTUwJxWFVkiQP0GMtSiQcLrT8kDAAAIABAACAAAAAgAIAAIABAAAAAAAAACICApzpA/cOm2pLz3ylHCe+Q3xSe3yqvUdSGgcshs6VMkAzEEH0COgBAACAAQAAAAAAAAAiAgNoGMdrRy+8wK8JkJ6DZbhGfW0eECVMbfG1yAHrAur4WQwOUpuGAQAAAAAAAAAAAA==

PSBT fingerprint (md5):
e22492816b17cbeb2a6f70513dbfbf73

QR code for signed psbt written to psbt-signed-01.png,psbt-signed-02.png
```
At this point, you can use the QR codes in `psbt-signed-01.png` and `psbt-signed-02.png` to transfer the signed PSBT back to your online watch-only wallet. After combining this PSBT with at least 1 additional signature, the PSBT can be finalized into a transaction that you can broadcast to the Bitcoin network.
