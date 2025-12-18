import argparse
import pprint
import xml.etree.ElementTree as ET

MEM_SIZE = 1024
mem = [0] * MEM_SIZE

def bitreverse(value, bits=32):
    return int(f"{value:0{bits}b}"[::-1], 2)


def execute(program):
    for op, b, c in program:

        if op == "load_const":
            mem[c] = b

        elif op == "read":
            mem[c] = mem[mem[b]]

        elif op == "write":
            mem[c] = mem[b]

        elif op == "bitrev":
            mem[b] = bitreverse(mem[c])

        else:
            raise ValueError(f"Unknown instruction: {op}")

def dump_memory_xml(start, end):
    root = ET.Element("memory")

    for addr in range(start, end):
        cell = ET.SubElement(root, "cell")
        cell.set("address", str(addr))
        cell.text = str(mem[addr])

    return ET.tostring(root, encoding="unicode")

def main():
    parser = argparse.ArgumentParser(description="UVM Interpreter (stage 2)")
    parser.add_argument(
        "--path", "-p", required=True, help="Path to intermediate representation file"
    )
    parser.add_argument(
        "--dump", "-d", required=True, help="Path to XML memory dump file"
    )
    parser.add_argument(
        "--range", "-r", required=True, help="Memory range to dump, e.g. 0-16"
    )

    args = parser.parse_args()

    # Загрузка промежуточного представления
    with open(args.path, encoding="utf-8") as f:
        program = eval(f.read())

    print("Program:")
    pprint.pprint(program)

    # Выполнение программы
    execute(program)

    # Дамп памяти
    start, end = map(int, args.range.split("-"))
    xml_dump = dump_memory_xml(start, end)

    with open(args.dump, "w", encoding="utf-8") as f:
        f.write(xml_dump)

    print(f"Memory dumped to {args.dump}")


if __name__ == "__main__":
    main()
