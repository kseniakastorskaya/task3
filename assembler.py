import argparse
import re
import pprint

# LOAD_CONST(146, 456)
CMD_RE = re.compile(r"(\w+)\((\d+),\s*(\d+)\)")

VALID_OPS = {
    "load_const",
    "read",
    "write",
    "bitrev",
}


def assemble(text):
    program = []

    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        m = CMD_RE.fullmatch(line)
        if not m:
            raise SyntaxError(f"Line {lineno}: invalid syntax")

        op = m.group(1).lower()
        b = int(m.group(2))
        c = int(m.group(3))

        if op not in VALID_OPS:
            raise SyntaxError(f"Line {lineno}: unknown instruction {op}")

        program.append((op, b, c))

    return program


def main():
    parser = argparse.ArgumentParser(description="UVM Assembler (stage 1)")
    parser.add_argument("--src", required=True, help="Source .asm file")
    parser.add_argument("--out", required=True, help="Output IR file")
    parser.add_argument("--test", action="store_true", help="Print IR")

    args = parser.parse_args()

    with open(args.src, encoding="utf-8") as f:
        text = f.read()

    program = assemble(text)

    if args.test:
        print("Intermediate representation:")
        pprint.pprint(program)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(repr(program))

    print(f"Written {len(program)} instructions to {args.out}")


if __name__ == "__main__":
    main()
