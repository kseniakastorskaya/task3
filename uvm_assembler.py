import argparse
import re
import sys
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple

# ---------------------- Assembler ----------------------
OPCODES = {
    "LOAD_CONST": (45, "SHORT"),
    "READ": (55, "FULL"),
    "WRITE": (14, "FULL"),
    "BITREV": (34, "FULL"),
}

TOKEN_RE = re.compile(r"^\s*([A-Za-z_.][A-Za-z0-9_.-]*)\s*(.*)$")
SET_RE = re.compile(r"^\.set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*$")
COMMENT_RE = re.compile(r"(#|;).*?$")


def parse_int(tok: str, symbols: Dict[str, int]) -> int:
    tok = tok.strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    if tok.isdigit():
        return int(tok, 10)
    if tok in symbols:
        return symbols[tok]
    raise ValueError(f"Unknown token for integer: '{tok}'")


def parse_line(line: str, symbols: Dict[str, int]) -> Tuple[str, List[int]]:
    m = TOKEN_RE.match(line)
    if not m:
        raise ValueError(f"Can't parse line: {line!r}")
    mnemonic = m.group(1).upper()
    rest = m.group(2).strip()
    if mnemonic == ".SET":
        raise ValueError(".set should be handled separately")
    if mnemonic not in OPCODES:
        raise ValueError(f"Unknown mnemonic: {mnemonic}")
    parts = [p.strip() for p in rest.split(",")]
    if len(parts) != 2:
        raise ValueError(f"Expected two arguments for {mnemonic}, got: {parts}")
    a1 = parse_int(parts[0], symbols)
    a2 = parse_int(parts[1], symbols)
    return mnemonic, [a1, a2]


def encode_instruction(opcode: int, fmt: str, B: int, C: int) -> Tuple[int, bytes]:
    A = opcode & 0x3F
    if fmt == "SHORT":
        val = A | (B << 6) | (C << 22)
    else:
        val = A | (B << 6) | (C << 23)
    b = bytes(((val >> (8 * i)) & 0xFF for i in range(5)))
    return val, b


def assemble_lines(lines: List[str]) -> Tuple[List[Dict], bytes]:
    symbols = {}
    program = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        line = COMMENT_RE.sub("", line).strip()
        if not line:
            continue
        mset = SET_RE.match(line)
        if mset:
            symbols[mset.group(1)] = int(mset.group(2), 0)
            continue
        mnemonic, args = parse_line(line, symbols)
        opcode, fmt = OPCODES[mnemonic]
        B, C = args[0], args[1]
        val, bts = encode_instruction(opcode, fmt, B, C)
        program.append(
            {
                "line": lineno,
                "mnemonic": mnemonic,
                "A": opcode,
                "B": B,
                "C": C,
                "value": val,
                "bytes": bts,
            }
        )
    out = b"".join(p["bytes"] for p in program)
    return program, out


# ---------------------- Interpreter ----------------------
class UVMMemory:
    def __init__(self, size=1024):
        self.mem = [0] * size

    def read(self, addr):
        return self.mem[addr]

    def write(self, addr, value):
        self.mem[addr] = value


def bitreverse(value: int, bits: int = 32) -> int:
    """
    Побитовый реверс числа value с указанным количеством бит.
    """
    bstr = f"{value:0{bits}b}"
    rev = int(bstr[::-1], 2)
    return rev


def run_interpreter(program: List[Dict], mem_size=1024) -> UVMMemory:
    memory = UVMMemory(mem_size)
    for instr in program:
        A = instr["A"]
        B = instr["B"]
        C = instr["C"]
        if A == 45:  # LOAD_CONST
            memory.write(C, B)
        elif A == 55:  # READ
            value = memory.read(B)
            memory.write(C, value)
        elif A == 14:  # WRITE
            value = memory.read(B)
            memory.write(C, value)
        elif A == 34:  # BITREV
            val = memory.read(C)
            rev_val = bitreverse(val, bits=32)
            memory.write(B, rev_val)
        else:
            raise ValueError(f"Unknown opcode {A}")
    return memory


def dump_memory_xml(memory: UVMMemory, start=0, end=16) -> str:
    root = ET.Element("memory")
    for addr in range(start, end):
        e = ET.SubElement(root, "cell", addr=str(addr))
        e.text = str(memory.read(addr))
    return ET.tostring(root, encoding="unicode")


# ---------------------- CLI ----------------------
def main():
    parser = argparse.ArgumentParser(description="UVm Assembler + Interpreter")
    parser.add_argument(
        "--assemble",
        nargs=2,
        metavar=("input.asm", "output.bin"),
        help="Assemble source file",
    )
    parser.add_argument(
        "--test", action="store_true", help="Print intermediate representation"
    )
    parser.add_argument(
        "--interpret",
        nargs=3,
        metavar=("input.bin", "dump.xml", "range"),
        help="Interpret program and dump memory",
    )
    args = parser.parse_args()

    if args.assemble:
        with open(args.assemble[0], "r", encoding="utf-8") as f:
            lines = f.readlines()
        program, outbytes = assemble_lines(lines)
        with open(args.assemble[1], "wb") as f:
            f.write(outbytes)
        if args.test:
            print("Assembled program (intermediate representation):")
            for instr in program:
                print(
                    f"Line {instr['line']:>3}: {instr['mnemonic']:12} A={instr['A']}, B={instr['B']}, C={instr['C']} -> {', '.join(f'0x{b:02X}' for b in instr['bytes'])}"
                )
        print(f"Wrote {len(outbytes)} bytes to {args.assemble[1]}")

    if args.interpret:
        infile, outxml, memrange = args.interpret
        with open(infile, "rb") as f:
            data = f.read()
        program = []
        for i in range(0, len(data), 5):
            val = sum(data[i + j] << (8 * j) for j in range(5))
            A = val & 0x3F
            if A == 45:
                B = (val >> 6) & 0xFFFF
                C = (val >> 22) & 0x1FFFF
            else:
                B = (val >> 6) & 0x1FFFF
                C = (val >> 23) & 0x1FFFF
            program.append({"A": A, "B": B, "C": C})
        start, end = map(int, memrange.split("-"))
        memory = run_interpreter(program)
        xmlstr = dump_memory_xml(memory, start, end)
        with open(outxml, "w", encoding="utf-8") as f:
            f.write(xmlstr)
        print(f"Memory dumped to {outxml} (addresses {start}-{end-1})")


if __name__ == "__main__":
    main()
