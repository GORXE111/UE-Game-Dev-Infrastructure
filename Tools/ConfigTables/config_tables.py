"""Validate typed CSV or XLSX tables and export deterministic Unreal DataTable JSON."""

import argparse
from contextlib import closing
import csv
import hashlib
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import struct
from tempfile import TemporaryDirectory

from table_contract import build_contract, parse_field_policy
from xml.etree.ElementTree import ParseError
from zipfile import BadZipFile


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
INTEGER = re.compile(r"[+-]?[0-9]+")
DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
RESERVED = {"manifest", "con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10))}
TYPES = {"bool", "float", "int", "string"}
INVALID_PATH_CHARACTERS = re.compile(r'[:<>"|?*\x00-\x1f]')
MAX_WORKSHEET_ROWS = 1_048_576


def require(condition, message):
    if not condition:
        raise ValueError(message)


def input_file(root, name):
    path = root
    parts = Path(name).parts
    for index, part in enumerate(parts):
        path /= part
        attributes = path.lstat()
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        require(expected(attributes.st_mode) and
                not getattr(attributes, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
                f"{name}: expected a regular file inside the source directory without links")
    return path


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"schema.json: duplicate key {key!r}")
        result[key] = value
    return result


def identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None and value.lower() != "none"


def source_options(table):
    if "source" not in table:
        return None
    label = f"schema.json: {table['name']} source"
    source = table["source"]
    require(type(source) is dict and "file" in source and source.keys() <= {"file", "sheet", "headerRow"},
            f"{label} needs file with optional sheet and headerRow")
    filename = source["file"]
    require(isinstance(filename, str), f"{label}.file must be a relative CSV or XLSX path")
    parts = filename.replace("\\", "/").split("/")
    require(all(part and part not in {".", ".."} and not part.endswith((" ", ".")) and
                not INVALID_PATH_CHARACTERS.search(part) and not PureWindowsPath(part).is_reserved() for part in parts),
            f"{label}.file must be a relative CSV or XLSX path inside the source directory")
    path = Path(*parts)
    require(path.suffix.lower() in {".csv", ".xlsx"}, f"{label}.file must name a CSV or XLSX file")
    sheet = source.get("sheet")
    require("sheet" not in source or (path.suffix.lower() == ".xlsx" and isinstance(sheet, str) and bool(sheet)),
            f"{label}.sheet must be a nonempty XLSX worksheet name")
    header_row = source.get("headerRow", 1)
    require(type(header_row) is int and 1 <= header_row <= MAX_WORKSHEET_ROWS,
            f"{label}.headerRow must be an integer from 1 to {MAX_WORKSHEET_ROWS}")
    return path, sheet, header_row


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
        require(type(table) is dict and {"name", "fields"} <= table.keys() <= {"name", "fields", "source"}
                and identifier(table["name"])
                and type(table["fields"]) is list and table["fields"],
                "schema.json: each table needs a valid name and a nonempty fields array")
        name = table["name"]
        require(name.lower() not in used_tables | RESERVED, f"schema.json: duplicate or reserved table {name!r}")
        used_tables.add(name.lower())
        fields = {}
        policies = {}
        used_fields = {"name"}
        for field in table["fields"]:
            require(type(field) is dict and {"name", "type"} <= field.keys() <= {"name", "type", "audience", "ref"}
                    and identifier(field["name"])
                    and isinstance(field["type"], str) and field["type"] in TYPES,
                    f"schema.json: {name} needs named fields of type bool, float, int or string")
            field_name = field["name"]
            require(field_name.lower() not in used_fields, f"schema.json: {name} has duplicate field {field_name!r}")
            used_fields.add(field_name.lower())
            fields[field_name] = field["type"]
            if "audience" in field or "ref" in field:
                policies[field_name] = parse_field_policy(field, f"schema.json: {name}.{field_name}")
        tables[name] = (fields, source_options(table), policies)
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


def csv_rows(path, filename, header_row):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for _ in range(header_row - 1):
            if not stream.readline():
                return
        reader = csv.reader(stream, strict=True)
        try:
            for cells in reader:
                yield f"{filename}:{header_row - 1 + reader.line_num}", cells
        except csv.Error as error:
            raise ValueError(f"{filename}:{header_row - 1 + reader.line_num}: {error}") from error


def claim_source(used_sources, filename, sheet=None):
    key = filename.casefold(), sheet.casefold() if sheet is not None else None
    label = filename if sheet is None else f"{filename}!{sheet}"
    require(key not in used_sources, f"{label}: the same source is already assigned to another table")
    used_sources.add(key)


def xlsx_rows(path, filename, name, width, sheet_name, header_row, used_sources):
    try:
        from defusedxml.common import DefusedXmlException
        from openpyxl import DEFUSEDXML, load_workbook
        from openpyxl.utils.exceptions import InvalidFileException
    except ImportError as error:
        raise ValueError(f'{filename}: install XLSX support with python -m pip install '
                         '"openpyxl>=3.1,<4" "defusedxml>=0.7,<1"') from error
    require(DEFUSEDXML, f"{filename}: enable defusedxml in openpyxl for XLSX input")

    try:
        with path.open("rb") as stream, closing(load_workbook(
                stream, read_only=True, data_only=False, keep_links=False)) as workbook:
            sheets = workbook.worksheets
            if sheet_name is not None:
                sheet = next((entry for entry in sheets if entry.title == sheet_name), None)
                require(sheet is not None, f"{filename}: worksheet {sheet_name!r} does not exist")
            else:
                sheet = next((entry for entry in sheets if entry.title.casefold() == name.casefold()), None)
                if sheet is None and len(sheets) == 1:
                    sheet = sheets[0]
                require(sheet is not None, f"{filename}: use a worksheet named {name!r} or a workbook with one worksheet")
            claim_source(used_sources, filename, sheet.title)
            location = f"{filename}!{sheet.title}"
            # Some workbook writers leave a stale used range. Read the cells actually present.
            sheet.reset_dimensions()
            for number, cells in enumerate(sheet.iter_rows(min_row=header_row), header_row):
                for cell in cells:
                    if cell.data_type == "f":
                        raise ValueError(f"{location}:{cell.coordinate}: replace formulas with literal values")
                    if cell.data_type == "e":
                        raise ValueError(f"{location}:{cell.coordinate}: resolve spreadsheet error {cell.value!r}")
                values = [cell.value for cell in cells]
                while values and values[-1] is None:
                    values.pop()
                if number > header_row and values:
                    values.extend([None] * (width - len(values)))
                yield f"{location}:{number}", ["" if value is None else value for value in values]
    except (BadZipFile, DefusedXmlException, InvalidFileException, ParseError, IndexError, KeyError, TypeError) as error:
        raise ValueError(f"{filename}: could not read XLSX workbook ({error})") from error


def load_rows(root, name, fields, source, used_sources, locations=None):
    if source is None:
        filenames = [f"{name}.csv", f"{name}.xlsx"]
        available = [filename for filename in filenames if os.path.lexists(root / filename)]
        require(len(available) == 1, f"{name}: provide exactly one of {filenames[0]} or {filenames[1]}")
        source = Path(available[0]), None, 1
    relative, sheet, header_row = source
    path = input_file(root, relative)
    filename = relative.as_posix()
    header = ["Name", *fields]
    rows = {}
    if path.suffix.lower() == ".csv":
        claim_source(used_sources, filename)
        records = csv_rows(path, filename, header_row)
    else:
        records = xlsx_rows(path, filename, name, len(header), sheet, header_row, used_sources)
    with closing(records):
        label, cells = next(records, (f"{filename}:{header_row}", None))
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
            if locations is not None:
                locations[row_name] = label
    require(bool(rows), f"{filename}: Unreal DataTable needs at least one data row")
    return [rows[key] for key in sorted(rows)]


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def render_bundle(version, rows_by_table, **identity):
    manifest = {"schemaVersion": version, **identity, "files": {}}
    payloads = {}
    for name, rows in rows_by_table.items():
        filename = name + ".json"
        data = json_bytes(rows)
        payloads[filename] = data
        manifest["files"][filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "rows": len(rows)}
    payloads["manifest.json"] = json_bytes(manifest)
    return manifest, payloads


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
    rows_by_table = {}
    locations = {}
    used_sources = set()
    for name in sorted(tables, key=str.lower):
        fields, table_source, _ = tables[name]
        locations[name] = {}
        rows_by_table[name] = load_rows(source, name, fields, table_source, used_sources, locations[name])

    if any(entry[2] for entry in tables.values()):
        contract = build_contract(version, {name: entry[0] for name, entry in tables.items()},
                                  {name: entry[2] for name, entry in tables.items()}, rows_by_table, locations)
        identity = {"compatibilitySha256": contract.compatibility_sha256}
        manifest, client = render_bundle(version, contract.client, **identity)
        _, server = render_bundle(version, contract.server, **identity, sourceSha256=contract.source_sha256)
        bundles = {"client": client, "server": server}
        manifest = {**manifest, "layout": "client-server"}
    else:
        manifest, payloads = render_bundle(version, rows_by_table)
        bundles = {"": payloads}

    if output is not None:
        with TemporaryDirectory(prefix=".config-tables-", dir=output.parent) as scratch:
            stage = Path(scratch) / "generated"
            stage.mkdir()
            for bundle, payloads in bundles.items():
                directory = stage / bundle
                directory.mkdir(exist_ok=True)
                for name, data in payloads.items():
                    (directory / name).write_bytes(data)
            require(not os.path.lexists(output), "Choose a new output directory")
            stage.rename(output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Directory containing schema.json and its CSV or XLSX inputs")
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
