from coincurve import PrivateKey
import binascii

# Replace with your WIF private key from Electrum
wif = "L4GEuzauS6xpG1M5Cp6iotwEQm1mEuUGDTtMDJe25jusQtWGqkdh"

# Convert WIF to raw private key bytes using 'bit'
from bit import Key
key = Key(wif)

# Get the raw private key bytes
priv_bytes = key.to_bytes()

# Create a coincurve PrivateKey object
priv = PrivateKey(priv_bytes)

# Get the compressed public key (33 bytes)
pub_bytes = priv.public_key.format(compressed=True)
pub_hex = binascii.hexlify(pub_bytes).decode()

print("Public key (hex):", pub_hex)