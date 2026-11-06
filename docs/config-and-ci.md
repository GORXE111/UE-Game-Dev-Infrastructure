# 配置表、资源检查和 Jenkins

从仓库根目录运行。打表需要 Python 3.11+，可在没有 UE 或 Excel 的机器上运行。UE 样板检查使用开发者自行安装的 Unreal Editor。

## 独立打表

1. 把 `Examples/ConfigTables` 的 `schema.json` 和 CSV 复制到项目自己的配置源目录。`Name` 是 UE DataTable 的行键。其他列按 schema 的顺序排列，类型支持 `int`（32 位）、`float`（有限值，32 位范围）、`bool`（`true` 或 `false`）和 `string`。每张表至少保留一条数据。
2. 用 UTF-8 CSV 保存数据。类型、表头和行名检查会在输出前执行。生成目录使用新路径，成功后包含每张表的 JSON 及 `manifest.json` 中的 SHA-256、字节数和行数。
3. 在 UE 内容浏览器导入 JSON，并选用与字段对应的 `FTableRowBase` 行类型。样例的 `GameplayTags.json` 使用引擎的 `GameplayTagTableRow`。`EnemyTuning.json` 的行类型由目标项目声明，字段为 `Health`、`MoveSpeed`、`bCanSprint` 和 `DisplayName`。 [Epic DataTable 导入约定](https://dev.epicgames.com/documentation/unreal-engine/data-driven-gameplay-elements-in-unreal-engine)

```powershell
python -X utf8 -B .\Tools\ConfigTables\config_tables.py `
  --source .\Examples\ConfigTables --check
python -X utf8 -B .\Tools\ConfigTables\config_tables.py `
  --source .\Examples\ConfigTables --output .\local-projects\ConfigExample
```

先创建输出的父目录 `local-projects`。将 schema 和 CSV 纳入版本控制，由构建节点生成 JSON。只需检查源表的任务可用 `--check`。

## UE 样板导入与资源检查

准备已启用 `PythonScriptPlugin` 的空白项目。以下脚本在该样板中创建 `/Game/AdoptionSmoke/DT_AdoptionConfigSmoke`，验证导入和导出后的中文文本与行键一致。可将脚本复制到短英文路径，以便跨引擎安装使用。

```powershell
$editor = 'C:\UE\Engine\Binaries\Win64\UnrealEditor-Cmd.exe'
$project = 'C:\Work\AdoptionConfigSample\AdoptionConfigSample.uproject'
$env:UE_ADOPTION_CONFIG_BUNDLE = (Resolve-Path .\local-projects\ConfigExample).Path
$import = (Resolve-Path .\Examples\ConfigTables\verify_ue_import.py).Path
& $editor $project -run=PythonScript "-script=$import" -Unattended -NullRHI -stdout
```

创建资产清单，例如 `C:\Work\required-assets.json`。

```json
{
  "version": 1,
  "assets": [
    {
      "path": "/Game/AdoptionSmoke/DT_AdoptionConfigSmoke.DT_AdoptionConfigSmoke",
      "class": "/Script/Engine.DataTable"
    }
  ]
}
```

```powershell
$env:UE_ADOPTION_ASSET_PLAN = 'C:\Work\required-assets.json'
$env:UE_ADOPTION_ASSET_REPORT = 'C:\Work\asset-report.json'
$check = (Resolve-Path .\Tools\AssetChecks\check_ue_assets.py).Path
& $editor $project -run=PythonScript "-script=$check" -Unattended -NullRHI -stdout
```

验收要求编辑器退出为 0 且报告为 `passed`。报告路径必须全新。资源检查逐项核对 Asset Registry、类和能否加载。Cook 产物的完整性、引用闭包和运行时加载另有独立验收。

## Jenkins 构建门禁

先在开发机执行 Jenkins 使用的同一个入口。需要 PowerShell 7、Python 3.11+ 和 `cryptography`。

```powershell
pwsh -NoProfile -File .\Tools\CI\Invoke-AdoptionChecks.ps1 `
  -OutputDirectory C:\Work\UE-Adoption-Checks-01
```

在 Jenkins 建立读取本仓库的 Pipeline，脚本路径为 `Jenkinsfile`。准备带 `windows` 标签的节点，并确保该节点的 `pwsh` 和 Python 来自预期安装。可在节点用 `UE_ADOPTION_PYTHON` 指定 Python 路径。每次构建归档报告、日志、生成的表和摘要。此入口检查配置、脚手架和离线签名流程，已通过 Windows 本机验证。Jenkins 控制器、UE Build、Cook、资源检查及发布任务各自需要在对应节点和环境验收。 [Jenkinsfile 指南](https://www.jenkins.io/doc/book/pipeline/jenkinsfile/) · [PowerShell 构建步骤](https://www.jenkins.io/doc/pipeline/steps/workflow-durable-task-step/)
