# Transaction fee constants
FEE_RATE_MULTIPLIER = 10**5 # BTC/kB -> sat/byte

# PSBT data model constants
PSBT_INPUTS = "inputs"
PSBT_OUTPUTS = "outputs"
PSBT_UNKNOWN = "unknown"
PSBT_TX = "tx"
PSBT_TX_TXID = "txid"
PSBT_VSIZE = "vsize"
PSBT_TX_VIN = "vin"
PSBT_TX_VOUT = "vout"
PSBT_TX_VALUE = "value"
PSBT_TX_ADDRESSES = "addresses"
PSBT_SCRIPTPUBKEY = "scriptPubKey"
PSBT_WITNESS_SCRIPT = "witness_script"
PSBT_ASM = "asm"
PSBT_HEX = "hex"
PSBT_TYPE = "type"
PSBT_SIGHASH = "sighash"
PSBT_ADDRESS = "address"
PSBT_WITNESS_UTXO = "witness_utxo"
PSBT_AMOUNT = "amount"
PSBT_NON_WITNESS_UTXO = "non_witness_utxo"
PSBT_BIP32_DERIVS = "bip32_derivs"
PSBT_BIP32_MASTER_FP = "master_fingerprint"
PSBT_BIP32_PATH = "path"
PSBT_FEE = "fee"
PSBT_WSH_TYPE = "witness_v0_scripthash"

# Analyze PSBT constants
ANALYZE_ESTIMATED_VSIZE = "estimated_vsize"
ANALYZE_ESTIMATED_FEERATE = "estimated_feerate"
