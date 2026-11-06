"""Validate shared table references and split typed rows by audience."""

from dataclasses import dataclass
import hashlib
import json
import re
import struct


TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


@dataclass(frozen=True)
class FieldPolicy:
    audience: str = "shared"
    ref: str | None = None


@dataclass(frozen=True)
class ConfigContract:
    client: dict
    server: dict
    compatibility_sha256: str
    source_sha256: str


def parse_field_policy(field, label):
    """Read the optional keys of an otherwise validated field declaration."""
    audience = field.get("audience", "shared")
    if audience not in ("shared", "server"):
        raise ValueError(f"{label}: audience must be 'shared' or 'server'")
    reference = field.get("ref")
    if "ref" in field and (field["type"] != "string" or not isinstance(reference, str)
                           or not TABLE_NAME.fullmatch(reference) or reference.lower() == "none"):
        raise ValueError(f"{label}: ref requires a string field and a target table name")
    if audience == "shared" and reference is None:
        return None
    return FieldPolicy(audience, reference)


def digest(value):
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_floats(rows, fields, locations):
    float_fields = [field for field, kind in fields.items() if kind == "float"]
    normalized = []
    for source_row in rows:
        row = dict(source_row)
        for field in float_fields:
            number = row[field]
            value = struct.unpack("<f", struct.pack("<f", number))[0]
            if value == 0.0 and number != 0.0:
                location = locations.get(row["Name"], row["Name"])
                raise ValueError(f"{location} ({field}): nonzero value underflows Unreal float32")
            row[field] = 0.0 if value == 0.0 else value
        normalized.append(row)
    return sorted(normalized, key=lambda row: row["Name"].casefold())


def build_contract(version, fields_by_table, policies_by_table, rows_by_table, locations_by_table):
    """Use exact declared table and row spellings for portable foreign keys."""
    server = {table: normalize_floats(rows_by_table[table], fields_by_table[table], locations_by_table.get(table, {}))
              for table in sorted(fields_by_table, key=str.casefold)}
    row_names = {table: {row["Name"] for row in rows} for table, rows in server.items()}
    client = {}
    shared_schema = {}
    full_schema = {}
    for table, rows in server.items():
        policies = policies_by_table.get(table, {})
        shared_fields = {}
        all_fields = {}
        for field, kind in fields_by_table[table].items():
            policy = policies.get(field) or FieldPolicy()
            field_schema = {"type": kind}
            if policy.ref is not None:
                if policy.ref not in row_names:
                    raise ValueError(f"schema.json: {table}.{field} references unknown table {policy.ref!r}")
                field_schema["ref"] = policy.ref
                for row in rows:
                    if row[field] not in row_names[policy.ref]:
                        name = row["Name"]
                        location = locations_by_table.get(table, {}).get(name, f"{table}:{name}")
                        raise ValueError(f"{location} ({field}): {row[field]!r} does not reference {policy.ref}.Name")
            all_fields[field] = {**field_schema, "audience": policy.audience}
            if policy.audience == "shared":
                shared_fields[field] = field_schema
        full_schema[table] = all_fields
        shared_schema[table] = shared_fields
        client[table] = [{"Name": row["Name"], **{field: row[field] for field in shared_fields}} for row in rows]

    compatibility_sha256 = digest({"contractVersion": 1, "fields": shared_schema, "tables": client})
    source_sha256 = digest({"contractVersion": 1, "schemaVersion": version, "fields": full_schema, "tables": server})
    return ConfigContract(client, server, compatibility_sha256, source_sha256)
