#!/usr/bin/python
#Brainfuck Decoder

import sys

ALLOWED_CHARS = '+-.,<>[]'
MEN_SIZE = 30000

def run(prog):
    mem = [0] * MEN_SIZE
    prog = ''.join(c for c in prog if c in ALLOWED_CHARS)
    matching_brackets = precompute_matching_brackets(prog)
    ip = 0 #Instruction Pointer
    dp = 0 #Data Pointer

    while ip < len(prog):
        inst = prog[ip]

        if inst == '>':
            dp += 1
        elif inst == '<':
            dp -= 1
        elif inst == '+':
            mem[dp] += 1
        elif inst == '-':
            mem[dp] -= 1
        elif inst == '.':
            sys.stdout.write(chr(mem[dp]))
        elif inst == ',':
            mem[dp] = ord(sys.stdin.read(1))
        elif inst == '[' and mem[dp] == 0:
            ip = matching_brackets[ip]
        elif inst == ']' and mem[dp] != 0:
            ip = matching_brackets[ip]

        ip += 1

def precompute_matching_brackets(prog):
    matching_brackets = {}
    stack = []
    for i, el in enumerate(prog):
        if el == '[':
            stack.append(i)
        elif el == ']':
            j = stack.pop()
            matching_brackets[i] = j
            matching_brackets[j] = i
    return matching_brackets

def main():
    if len(sys.argv) != 2:
        print ("Usage:")
        print (sys.argv[0], '[FILE]')
        return

    with open(sys.argv[1]) as f:
        run(f.read())

if __name__ == '__main__':
    main()
