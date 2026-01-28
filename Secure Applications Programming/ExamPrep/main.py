# Script to generate the mystery file
from binascii import unhexlify

# Define the ciphertext (in hex)
ciphertext_hex = "D421D4351C0FB3DE414733E03D5EBABC"

# Convert to raw bytes
ciphertext_bytes = unhexlify(ciphertext_hex)

# Write to file
filename = "Msg.enc"
with open(filename, "wb") as f:
    f.write(ciphertext_bytes)

print(f"Successfully created '{filename}' with the mystery data.")