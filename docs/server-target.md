# 构建和验收 Win64 专服

```powershell
python -X utf8 -B .\Tools\Adoption\server_capability.py --engine E:\UE
```

`installed-ready` 表示安装版提供 Win64 Development Server 登记和对应构建产物。`source-ready-to-plan` 表示源码与构建工具可用于生成计划，`precompiledServer` 会单独说明已有二进制的情况。`blocked` 表示当前引擎缺少所需支持。

构建前选择支持 Server 的源码版 UE 或启用了 `WithServer` 的 Installed Build。源码本机验证使用独立项目输出和 `TargetType.Server`，`BuildEnvironment` 设为 `TargetBuildEnvironment.Unique`，让主要中间产物落在隔离项目。使用短路径和容量充足的磁盘。

以下命令面向已配置 `<Game>Server.Target.cs` 的独立项目。`-SkipBuild` 检查 Target 和工具链并生成规划文件。首次完整构建耗时取决于 UE 源码和现有中间产物。

```powershell
& 'E:\UE\Engine\Build\BatchFiles\Build.bat' GameServer Win64 Development `
  '-Project=D:\UESrv\Game.uproject' -IgnoreJunk -NoUBA -MaxParallelActions=2 -SkipBuild
```

## 运行独立样板

先运行 [network-profile](project-profile.md#双端配置和本机联机)，取得通过验收的 Win64 客户端报告。以下命令复用该次导入得到的 DataTable 和共享配置摘要，专服仍单独编译、Cook 和归档。示例路径对应全新的输出目录。

```powershell
$clientReport = 'D:\UEClient\report.json'
pwsh -NoProfile -File .\Tools\Adoption\New-ServerSample.ps1 `
  -ProfileReport $clientReport -OutputDirectory D:\UESrv

pwsh -NoProfile -File .\Tools\Adoption\Invoke-ServerProfile.ps1 `
  -Project D:\UESrv\Project\ProfileSample.uproject -EngineRoot E:\UE `
  -ServerConfigDirectory D:\UESrv\ServerConfig -OutputDirectory D:\UESrvPack

pwsh -NoProfile -File .\Tools\Adoption\Invoke-LoopbackSession.ps1 `
  -ProfileReport $clientReport -DedicatedReport D:\UESrvPack\report.json `
  -OutputDirectory D:\UESrvSession
```

首次编译需要为 Win64 Server 目标生成独立的中间产物。可用 `-MaxParallelActions` 限制并行任务数，必要时指定 `-ClangRoot` 和 `-PythonExecutable`。再次打包时可沿用隔离项目，另选新的归档输出目录。已有对应专服二进制与 UBT 回执时，可用 `-SkipBuild` 跳过 Server 编译。已有 Editor 模块且 Build ID 与所选引擎一致时，可用 `-SkipEditorBuild`。

归档工具核对 Server 类型的 UBT 回执、归档 EXE 的 SHA-256、PAK 中的入口地图和共享配置标记。归档报告保存专服配置目录及清单 SHA-256。配置目录单独交付给专服，客户端包使用自己的 DataTable。

样板用 `-AdoptionServerConfigDir` 和 `-AdoptionServerManifestSha256` 指定专服配置。清单摘要应从可信构建记录取得。专服校验清单和表文件后读取敌人与波次配置，再记录就绪。联机测试先篡改一份配置副本，检查专服在就绪前失败退出，再用原配置检查客户端进图、不兼容拒绝、重新连接和进程清理。测试报告的 `scope` 为 `win64-loopback-dedicated`。

[Epic 专服构建指南](https://dev.epicgames.com/documentation/unreal-engine/setting-up-dedicated-servers-in-unreal-engine)
