# Unreal plugin scaffold

`New-UEPlugin.ps1` writes a minimal UE C++ plugin descriptor, Build.cs, and module implementation. It supports Runtime and Editor module types and refuses to overwrite a non-empty output directory.

Run from the repository root:

```powershell
pwsh -File .\Tools\Scaffold\New-UEPlugin.ps1 `
  -PluginName ExampleGameplay `
  -OutputDirectory .\Project\SampleGame\Plugins\ExampleGameplay `
  -ModuleType Runtime
```

The scaffold uses only Unreal Build Tool's standard `Core`, `CoreUObject`, and `Engine` modules. Add project-specific dependencies and test it with the exact editor/game targets you ship.
