# Win64 专服能力预检

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

后续用 Server Target 单独 Cook 和打包。专服启动时还要加载服务端配置目录并核对清单，再与打包客户端验证进图、拒绝不兼容版本、断线重连和进程清理。 [Epic 专服构建指南](https://dev.epicgames.com/documentation/unreal-engine/setting-up-dedicated-servers-in-unreal-engine)
