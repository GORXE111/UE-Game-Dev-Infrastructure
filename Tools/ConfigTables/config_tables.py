"""Validate typed CSV tables and export deterministic Unreal DataTable JSON."""

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
from tempfile import TemporaryDirectory


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
INTEGER = re.compile(r"[+-]?[0-9]+")
DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
RESERVED = {"manifest", "con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10))}
TYPES = {"bool", "float", "int", "string"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def input_file(root, name):
    path = root / name
    attributes = path.lstat()
    require(stat.S_ISREG(attributes.st_mode) and
            not getattr(attributes, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            f"{name}: expected a regular file in the source directory")
    return path


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"schema.json: duplicate key {key!r}")
        result[key] = value
    return result


def identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None and value.lower() != "none"


def load_schema(root):
    schema = json.loads(input_file(root, "schema.json").read_text(encoding="utf-8-sig"),
                        object_pairs_hook=unique_keys)
    require(type(schema) is dict and schema.keys() == {"version", "tables"}
            and type(schema["version"]) is int and schema["version"] > 0
            and type(schema["tables"]) is list and schema["tables"],
            "schema.json: expected a positive integer version and a nonempty tables array")
    tables = {}
    used_tables = set()
    for table in schema["tables"]:
        require(type(table) is dict and table.keys() == {"name", "fields"} and identifier(table["name"])
                and type(table["fields"]) is list and table["fields"],
                "schema.json: each table needs a valid name and a nonempty fields array")
        name = table["name"]
        require(name.lower() not in used_tables | RESERVED, f"schema.json: duplicate or reserved table {name!r}")
        used_tables.add(name.lower())
        fields = {}
        used_fields = {"name"}
        for field in table["fields"]:
            require(type(field) is dict and field.keys() == {"name", "type"} and identifier(field["name"])
                    and isinstance(field["type"], str) and field["type"] in TYPES,
                    f"schema.json: {name} needs named fields of type bool, float, int or string")
            field_name = field["name"]
            require(field_name.lower() not in used_fields, f"schema.json: {name} has duplicate field {field_name!r}")
            used_fields.add(field_name.lower())
            fields[field_name] = field["type"]
        tables[name] = fields
    return schema["version"], tables


def value_for(raw, kind, label):
    if kind == "string":
        return raw
    if kind == "bool" and raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if kind == "int" and INTEGER.fullmatch(raw):
        integer = int(raw)
        require(-(2**31) <= integer < 2**31, f"{label}: integer is outside the Unreal int32 range")
        return integer
    if kind == "float" and DECIMAL.fullmatch(raw):
        number = float(raw)
        require(math.isfinite(number), f"{label}: expected a finite float")
        try:
            struct.pack("<f", number)
        except OverflowError as error:
            raise ValueError(f"{label}: float is outside the Unreal float32 range") from error
        return number
    raise ValueError(f"{label}: expected {kind}")


def load_rows(root, name, fields):
    filename = name + ".csv"
    with input_file(root, filename).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, strict=True)
        rows = {}
        try:
            require(next(reader, None) == ["Name", *fields], f"{filename}: header must match Name and schema fields")
            for cells in reader:
                if not cells:
                    continue
                label = f"{filename}:{reader.line_num}"
                require(len(cells) == len(fields) + 1, f"{label}: expected {len(fields) + 1} columns")
                row_name = cells[0]
                require(identifier(row_name), f"{label}: invalid row Name {row_name!r}")
                key = row_name.lower()
                require(key not in rows, f"{label}: duplicate row Name {row_name!r}")
                rows[key] = {"Name": row_name, **{
                    field: value_for(raw, kind, f"{label} ({field})")
                    for (field, kind), raw in zip(fields.items(), cells[1:])
                }}
        except csv.Error as error:
            raise ValueError(f"{filename}:{reader.line_num}: {error}") from error
    require(bool(rows), f"{filename}: Unreal DataTable needs at least one data row")
    return [rows[key] for key in sorted(rows)]


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def export_tables(source, output=None):
    source = Path(source).resolve(strict=True)
    require(source.is_dir(), "Choose a source directory")
    if output is not None:
        output = Path(output).absolute()
        require(not os.path.lexists(output), "Choose a new output directory")
        output = output.resolve()
        require(not output.is_relative_to(source) and output.parent.is_dir(),
                "Choose an output outside the source directory with an existing parent")

    version, tables = load_schema(source)
    manifest = {"schemaVersion": version, "files": {}}
    payloads = {}
    for name in sorted(tables, key=str.lower):
        rows = load_rows(source, name, tables[name])
        filename = name + ".json"
        data = json_bytes(rows)
        payloads[filename] = data
        manifest["files"][filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "rows": len(rows)}

    if output is not None:
        with TemporaryDirectory(prefix=".config-tables-", dir=output.parent) as scratch:
            stage = Path(scratch) / "generated"
            stage.mkdir()
            for name, data in payloads.items():
                (stage / name).write_bytes(data)
            (stage / "manifest.json").write_bytes(json_bytes(manifest))
            require(not os.path.lexists(output), "Choose a new output directory")
            stage.rename(output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Directory containing schema.json and table CSVs")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New destination directory for JSON and its manifest")
    mode.add_argument("--check", action="store_true", help="Validate without writing files")
    args = parser.parse_args()
    try:
        manifest = export_tables(args.source, args.output)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, ensure_ascii=True))
        return 1
    print(json.dumps({"status": "config-validated" if args.check else "config-exported", **manifest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
