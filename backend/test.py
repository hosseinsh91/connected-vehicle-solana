from solders.keypair import Keypair
from solders.pubkey import Pubkey
import json

with open("backend/global_wallet.json", "r") as f:
    keypair_data = json.load(f)
if len(keypair_data) != 64:
    raise ValueError("Invalid keypair: must be 64 bytes")
secret = bytes(keypair_data)
keypair = Keypair.from_bytes(secret)
print("Public key:", str(keypair.pubkey()))