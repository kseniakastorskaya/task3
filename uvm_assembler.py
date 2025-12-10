import argparse
import re
import sys
from typing import List, Dict, Tuple

# Opcode map and which format to use
OPCODES = {
    "LOAD_CONST": (45, "SHORT"),  # uses B:16 bits, C:17 bits (C << 22)
    "READ": (55, "FULL"),  # uses B:17, C:17 (C << 23)
    "WRITE": (14, "FULL"),
    "BITREV": (34, "FULL"),
}

# Helpers for parsing
TOKEN_RE = re.compile(r"^\s*([A-Za-z_.][A-Za-z0-9_.-]*)\s*(.*)$")
SET_RE = re.compile(r"^\.set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*$")
COMMENT_RE = re.compile(r"(#|;)\s*.*$")


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
    """Parse a non-empty, non-comment line into (mnemonic, [arg1,arg2])"""
    m = TOKEN_RE.match(line)
    if not m:
        raise ValueError(f"Can't parse line: {line!r}")
    mnemonic = m.group(1).upper()
    rest = m.group(2).strip()
    if mnemonic == ".SET":
        # handled elsewhere
        raise ValueError(".set should be handled separately")
    if mnemonic not in OPCODES:
        raise ValueError(f"Unknown mnemonic: {mnemonic}")
    if not rest:
        raise ValueError(f"Missing arguments for {mnemonic}")
    # split by comma
    parts = [p.strip() for p in rest.split(",")]
    if len(parts) != 2:
        raise ValueError(f"Expected two arguments for {mnemonic}, got: {parts}")
    a1 = parse_int(parts[0], symbols)
    a2 = parse_int(parts[1], symbols)
    return mnemonic, [a1, a2]


def encode_instruction(opcode: int, fmt: str, B: int, C: int) -> Tuple[int, bytes]:
    """Return (A,B,C) packed value and 5-byte little-endian bytes"""
    A = opcode & 0x3F
    if fmt == "SHORT":
        # B:16 bits, C:17 bits starting at bit 22
        if B >= (1 << 16) or C >= (1 << 17):
            raise ValueError(f"Field overflow for SHORT format: B={B}, C={C}")
        val = A | (B << 6) | (C << 22)
    elif fmt == "FULL":
        # B:17 bits (bits 6..22), C:17 bits (23..39)
        if B >= (1 << 17) or C >= (1 << 17):
            raise ValueError(f"Field overflow for FULL format: B={B}, C={C}")
        val = A | (B << 6) | (C << 23)
    else:
        raise ValueError("Unknown format")
    b = bytes(((val >> (8 * i)) & 0xFF for i in range(5)))
    return val, b


def assemble_lines(lines: List[str]) -> Tuple[List[Dict], bytes]:
    symbols = {}
    program = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        # strip inline comments
        line = COMMENT_RE.sub("", line).strip()
        if not line:
            continue
        # .set directive
        mset = SET_RE.match(line)
        if mset:
            name = mset.group(1)
            val = int(mset.group(2), 0)
            symbols[name] = val
            continue
        # parse instruction
        mnemonic, args = parse_line(line, symbols)
        opcode, fmt = OPCODES[mnemonic]
        B, C = args[0], args[1]
        # For LOAD_CONST the spec says argument order is B=constant, C=address
        # For other mnemonics it's (B_addr, C_addr) as given in examples.
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
    # concatenate bytes
    out = b"".join(p["bytes"] for p in program)
    return program, out


def main():
    parser = argparse.ArgumentParser(description="UVm assembler (stage 1)")
    parser.add_argument("input", help="Path to assembly source (.asm)")
    parser.add_argument("output", help="Path to binary output (.bin)")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Testing mode: print internal representation",
    )
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Failed to open input file: {e}")
        sys.exit(2)

    try:
        program, outbytes = assemble_lines(lines)
    except Exception as e:
        print(f"Assembly error: {e}")
        sys.exit(3)

    # write binary
    try:
        with open(args.output, "wb") as f:
            f.write(outbytes)
    except Exception as e:
        print(f"Failed to write output file: {e}")
        sys.exit(4)

    if args.test:
        # print internal representation in the format of the spec tests
        print("Assembled program (intermediate representation):")
        for instr in program:
            A = instr["A"]
            B = instr["B"]
            C = instr["C"]
            b = instr["bytes"]
            hexbytes = ", ".join(f"0x{bb:02X}" for bb in b)
            print(
                f"Line {instr['line']:>3}: {instr['mnemonic']:12} A={A}, B={B}, C={C} -> {hexbytes}"
            )
        # Also show per-field encoding in decimal+hex as in spec
        print("\nDetailed fields (like spec tests):")
        for instr in program:
            print(
                f"A={instr['A']}, B={instr['B']}, C={instr['C']}: {', '.join(f'0x{bb:02X}' for bb in instr['bytes'])}"
            )

    print(f"Wrote {len(outbytes)} bytes to {args.output}")


if __name__ == "__main__":
    main()
