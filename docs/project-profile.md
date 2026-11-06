# 用一个配置验收 UE 项目

从 [ProjectProfile 样板](../Examples/ProjectProfile/profile.json) 起步。只需要本地 UE 安装、对应的 Win64 C++ 工具链、PowerShell 7 和 Python 3.11+。打表输入包含 XLSX 时，还需安装[工作簿依赖](config-and-ci.md#独立打表)。UE 安装须提供 UnrealEditor-Cmd、PythonScriptPlugin、UAT 和 UnrealPak。

## 配置字段

| 字段 | 用途 |
| --- | --- |
| `version` | 配置格式版本，当前为 `1` |
| `project`、`configSource`、`assetPlan` | `.uproject`、表目录、资源清单。相对于 profile 文件，解析后的文件仍须在 profile 目录内 |
| `dataTables` | 将表名映射到新的 `/Game/` DataTable 对象路径和实际 UE 行结构。每项资产都应出现在资源清单里 |
| `build` | `target`、`platform`、`configuration` 和待 Cook 地图 `maps`。当前支持 Win64 Development。`editorTarget` 默认为游戏 Target 加 `Editor` |
| `startup` | 从已声明的地图选择启动入口。`readyMarker` 由游戏在真实初始化完成时写入日志 |
| `serverTarget` | 可选的服务器 Target 声明，供后续专用服务器阶段使用 |

资源清单逐项声明完整对象路径和类，使用 `/Game` 或 `/Engine`。资产名和地图包名沿用编辑器中的实际大小写。生成的 DataTable 使用工程内的新路径。生成目录适合专门放置可由源表重建的资产。

## 运行验收

```powershell
pwsh -NoProfile -File .\Tools\Adoption\Invoke-ProjectProfile.ps1 `
  -Profile .\Examples\ProjectProfile\profile.json `
  -EngineRoot C:\UE `
  -OutputDirectory C:\Work\UE-ProjectProfile-01
```

如需自定义工具链，使用 `-PythonExecutable`、`-ClangRoot` 和 `-MaxParallelActions`。输出目录使用全新短英文路径，位置在源 `.uproject` 目录外。脚本复制工程的标准源目录到输出中，再写入生成表与测试打包配置。源工程和源表可以继续用于日常编辑。样板打包使用 PAK 和传统 Cook 输出。首次运行可能等待着色器编译。

1. 生成表 JSON，记录 `ConfigTables/manifest.json` 的摘要。
2. 编译 Editor Target，在隔离工程里导入表，并用另一个编辑器进程从 Asset Registry 核对、加载实际落盘资产。
3. Build、Cook、Stage 和归档 Win64 包。使用 UnrealPak 的真实清单核对声明的地图和资产包，记录它们所在的 PAK 与大小。
4. 以 `-AdoptionProfileSmoke` 无头启动归档内的程序。样板在地图进入 BeginPlay 后加载 Cook 的 DataTable，核对行键、标签和中文备注，再写入就绪标记并正常退出。接入自己的项目时实现同一启动开关和对应的就绪逻辑。

`report.json` 给出失败阶段或 `project-profile-passed`。可从 `asset-report.json`、`cooked-assets.json` 和 `packaged-game.log` 复查每项证据。此流程检查列出的地图和资产。全量依赖、软引用闭包和包体预算须使用项目自己的检查规则。

Jenkins 的 `RUN_PROJECT_PROFILE` 可选择在配置了 `UE_ADOPTION_ENGINE_ROOT` 的 Windows 节点上执行同一脚本。`PROJECT_PROFILE` 是本次检出中项目配置的相对路径。作业将 `ci-evidence/<构建号>/ProjectProfile` 下的报告与回执归档，供后续阶段核对。专用服务器、Android 和公网发布各有独立验收。

Windows 构建节点使用独立的短工作区，例如 `E:\UECI`。在本次验收的 UE 5.8 UAT 中，路径里的 `Programs` 目录段会被重写为 `Source/Programs`，而重定向到很深的用户目录会触发 UBT 路径长度限制。把 Jenkins 的工作区与控制器程序目录分开可以避开两者。

## 构建回执

Jenkins 使用 `-RequireBuildReceipt`。本地可在干净的 Git 检出中加同一选项。游戏正常启动并退出后，脚本写出 `build-receipt.json`。回执记录项目提交、UE 版本及 Build ID、实际编译器和 Windows SDK、配置清单摘要、测试状态，以及归档中每个文件的 SHA-256 和大小。启动时使用独立用户目录，避免游戏日志和存档进入交付包。

从可信构建记录取得 `report.json` 中的 `buildReceiptSha256`，在签名交接前用它核对同一份归档。

```powershell
python -X utf8 -B .\Tools\Adoption\build_receipt.py verify `
  --archive C:\Work\UE-ProjectProfile-01\Archive\Windows `
  --receipt C:\Work\UE-ProjectProfile-01\build-receipt.json `
  --expected-receipt-sha256 $trustedReceiptSha256
```

回执替换、文件变化、缺失和新增都会使命令失败。签名阶段需使用刚校验的同一份不可变产物。

## 双端配置和本机联机

将 `-Profile` 改为 `Examples/ProjectProfile/network-profile.json`。此样板把敌人和波次表导出到客户端与服务端目录，检查波次引用的敌人存在，只把客户端数据导入 DataTable，并把共享配置摘要收入 PAK。客户端游戏启动时检查实际 Cook 的敌人和波次行。

```powershell
pwsh -NoProfile -File .\Tools\Adoption\Invoke-LoopbackSession.ps1 `
  -ProfileReport C:\Work\UE-ProjectProfile-01\report.json `
  -OutputDirectory C:\Work\UE-Loopback-01
```

样板用一个 Win64 游戏进程充当只监听 `127.0.0.1` 的主机，再启动客户端依次验证连入、配置不兼容拒绝和重新连入。成功连入须收到服务器 RPC，并与包内的共享摘要一致。脚本清理自己启动的测试进程，并留下主机和客户端日志。该报告标为 `win64-loopback-listen`。可复用这份客户端构建报告来[构建专用 Server 目标并验收服务端 JSON](server-target.md#运行独立样板)。
