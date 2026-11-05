# Unreal project and plugin scaffolds

Use PowerShell 7 and choose an output directory that does not exist yet. Paths are resolved from your current PowerShell location. Each script stages the files next to the destination and moves the complete tree into place. A second run against the same path fails before writing to it.

From the repository root, create a minimal C++ Unreal project and add a plugin to it.

```powershell
pwsh -File .\Tools\Scaffold\New-UEProject.ps1 `
  -ProjectName ExampleGame `
  -OutputDirectory '.\local-projects\Example Game' `
  -EngineAssociation '5.8'

pwsh -File .\Tools\Scaffold\New-UEPlugin.ps1 `
  -PluginName ExampleGameplay `
  -OutputDirectory '.\local-projects\Example Game\Plugins\ExampleGameplay' `
  -ModuleType Runtime
```

`New-UEProject.ps1` generates the `.uproject` descriptor, game and editor targets, and primary game module. Use the association for your installed engine, or leave it blank and open the descriptor with your selected Unreal Editor. Add a map and select the startup map before packaging a playable build.

`New-UEPlugin.ps1` generates the descriptor, module rules and source for a `Runtime` or `Editor` plugin. The generated project and plugin use the standard `Core`, `CoreUObject` and `Engine` modules. They start with stock Unreal behavior. Managed updates require a separate project integration and release configuration.
