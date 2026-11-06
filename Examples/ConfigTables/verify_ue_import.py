"""Verify a generated GameplayTags table in a disposable Unreal project."""

import json
import os
from pathlib import Path

import unreal


def verify():
    bundle = Path(os.environ["UE_ADOPTION_CONFIG_BUNDLE"]).resolve(strict=True)
    source = (bundle / "GameplayTags.json").read_text(encoding="utf-8")
    expected = {row["Name"]: (row["Tag"], row["DevComment"]) for row in json.loads(source)}
    asset_name = "DT_AdoptionConfigSmoke"
    asset_dir = "/Game/AdoptionSmoke"
    asset_path = f"{asset_dir}/{asset_name}.{asset_name}"
    assets = unreal.get_editor_subsystem(unreal.EditorAssetSubsystem)
    if assets.does_asset_exist(asset_path):
        raise RuntimeError(f"Choose a fresh sample project; {asset_path} already exists")

    row_struct = unreal.GameplayTagTableRow.static_struct()
    factory = unreal.DataTableFactory()
    factory.set_editor_property("struct", row_struct)
    table = unreal.AssetToolsHelpers.get_asset_tools().create_asset(asset_name, asset_dir, unreal.DataTable, factory)
    if not isinstance(table, unreal.DataTable) or table.get_row_struct() != row_struct:
        raise RuntimeError("Could not create the sample DataTable")
    tables = unreal.DataTableFunctionLibrary
    if not tables.fill_data_table_from_json_string(table, source):
        raise RuntimeError("Unreal rejected the generated JSON")
    actual = {row["Name"]: (row["Tag"], row["DevComment"])
              for row in json.loads(tables.export_data_table_to_json_string(table))}
    if actual != expected or not assets.save_loaded_asset(table, False):
        raise RuntimeError("Unreal could not preserve the generated rows")
    unreal.log(f"UE_CONFIG_TABLE_IMPORT_PASSED rows={len(actual)} asset={asset_path}")


verify()
