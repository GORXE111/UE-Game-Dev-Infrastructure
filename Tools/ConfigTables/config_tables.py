"""Validate typed CSV or XLSX tables and export deterministic Unreal DataTable JSON."""

import argparse
from contextlib import closing
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
from xml.etree.ElementTree import ParseError
from zipfile import BadZipFile


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
    if kind == "string" and isinstance(raw, str):
        return raw
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw.lower() in {"true", "false"}:
            return raw.lower() == "true"
    is_integer = type(raw) is int or (type(raw) is float and raw.is_integer())
    if kind == "int" and (is_integer or (isinstance(raw, str) and INTEGER.fullmatch(raw))):
        integer = int(raw)
        require(-(2**31) <= integer < 2**31, f"{label}: integer is outside the Unreal int32 range")
        return integer
    if kind == "float" and (type(raw) in {int, float} or (isinstance(raw, str) and DECIMAL.fullmatch(raw))):
        number = float(raw)
        require(math.isfinite(number), f"{label}: expected a finite float")
        try:
            struct.pack("<f", number)
        except OverflowError as error:
            raise ValueError(f"{label}: float is outside the Unreal float32 range") from error
        return number
    raise ValueError(f"{label}: expected {kind}")


def csv_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, strict=True)
        try:
            for cells in reader:
                yield f"{path.name}:{reader.line_num}", cells
        except csv.Error as error:
            raise ValueError(f"{path.name}:{reader.line_num}: {error}") from error


def xlsx_rows(path, name, width):
    try:
        from defusedxml.common import DefusedXmlException
        from openpyxl import DEFUSEDXML, load_workbook
        from openpyxl.utils.exceptions import InvalidFileException
    except ImportError as error:
        raise ValueError(f'{path.name}: install XLSX support with python -m pip install '
                         '"openpyxl>=3.1,<4" "defusedxml>=0.7,<1"') from error
    require(DEFUSEDXML, f"{path.name}: enable defusedxml in openpyxl for XLSX input")

    try:
        with path.open("rb") as stream, closing(load_workbook(
                stream, read_only=True, data_only=False, keep_links=False)) as workbook:
            sheets = workbook.worksheets
            sheet = next((entry for entry in sheets if entry.title.casefold() == name.casefold()), None)
            if sheet is None and len(sheets) == 1:
                sheet = sheets[0]
            require(sheet is not None, f"{path.name}: use a worksheet named {name!r} or a workbook with one worksheet")
            # Some workbook writers leave a stale used range. Read the cells actually present.
            sheet.reset_dimensions()
            for number, cells in enumerate(sheet.rows, 1):
                for cell in cells:
                    if cell.data_type == "f":
                        raise ValueError(f"{path.name}!{sheet.title}:{cell.coordinate}: replace formulas with literal values")
                    if cell.data_type == "e":
                        raise ValueError(f"{path.name}!{sheet.title}:{cell.coordinate}: resolve spreadsheet error {cell.value!r}")
                values = [cell.value for cell in cells]
                while values and values[-1] is None:
                    values.pop()
                if number > 1 and values:
                    values.extend([None] * (width - len(values)))
                yield f"{path.name}!{sheet.title}:{number}", ["" if value is None else value for value in values]
    except (BadZipFile, DefusedXmlException, InvalidFileException, ParseError, IndexError, KeyError, TypeError) as error:
        raise ValueError(f"{path.name}: could not read XLSX workbook ({error})") from error


def load_rows(root, name, fields):
    filenames = [f"{name}.csv", f"{name}.xlsx"]
    available = [filename for filename in filenames if os.path.lexists(root / filename)]
    require(len(available) == 1, f"{name}: provide exactly one of {filenames[0]} or {filenames[1]}")
    path = input_file(root, available[0])
    header = ["Name", *fields]
    rows = {}
    with closing(csv_rows(path) if path.suffix == ".csv" else xlsx_rows(path, name, len(header))) as records:
        label, cells = next(records, (path.name, None))
        require(cells == header, f"{label}: header must match Name and schema fields")
        for label, cells in records:
            if not cells:
                continue
            require(len(cells) == len(header), f"{label}: expected {len(header)} columns")
            row_name = cells[0]
            require(identifier(row_name), f"{label}: invalid row Name {row_name!r}")
            key = row_name.lower()
            require(key not in rows, f"{label}: duplicate row Name {row_name!r}")
            rows[key] = {"Name": row_name, **{
                field: value_for(raw, kind, f"{label} ({field})")
                for (field, kind), raw in zip(fields.items(), cells[1:])
            }}
    require(bool(rows), f"{path.name}: Unreal DataTable needs at least one data row")
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
    parser.add_argument("--source", type=Path, required=True, help="Directory containing schema.json and one CSV or XLSX per table")
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
