"""Import profile-mapped, generated tables into the staged Unreal project."""

import hashlib
import json
import os
from pathlib import Path

import unreal


def main():
    profile = json.loads(Path(os.environ["UE_ADOPTION_NORMALIZED_PROFILE"]).read_text(encoding="utf-8"))
    bundle = Path(os.environ["UE_ADOPTION_CONFIG_BUNDLE"])
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assets = unreal.get_editor_subsystem(unreal.EditorAssetSubsystem)
    factory_tools = unreal.AssetToolsHelpers.get_asset_tools()
    imports = []
    for mapping in profile["dataTables"]:
        filename = mapping["table"] + ".json"
        record = manifest["files"][filename]
        raw = (bundle / filename).read_bytes()
        if len(raw) != record["size"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise RuntimeError(f"Generated table does not match its manifest: {filename}")
        source = raw.decode("utf-8")
        rows = {row["Name"] for row in json.loads(source)}
        if len(rows) != record["rows"]:
            raise RuntimeError(f"Generated table row count changed: {filename}")
        path = mapping["asset"]
        if assets.does_asset_exist(path):
            raise RuntimeError(f"Choose a new generated asset path in the profile: {path}")
        row_struct = unreal.load_object(None, mapping["rowStruct"])
        if not isinstance(row_struct, unreal.ScriptStruct):
            raise RuntimeError(f"Cannot load UE row struct: {mapping['rowStruct']}")
        imports.append((path, source, rows, row_struct))

    for path, source, rows, row_struct in imports:
        directory, name = path.split(".", 1)[0].rsplit("/", 1)
        factory = unreal.DataTableFactory()
        factory.set_editor_property("struct", row_struct)
        table = factory_tools.create_asset(name, directory, unreal.DataTable, factory)
        if (not isinstance(table, unreal.DataTable) or table.get_row_struct() != row_struct
                or not unreal.DataTableFunctionLibrary.fill_data_table_from_json_string(table, source)
                or {str(name) for name in table.get_row_names()} != rows or not assets.save_loaded_asset(table, False)):
            raise RuntimeError(f"Could not import and save the generated DataTable: {path}")
    unreal.log(f"UE_ADOPTION_PROFILE_TABLES_IMPORTED count={len(imports)}")


main()
