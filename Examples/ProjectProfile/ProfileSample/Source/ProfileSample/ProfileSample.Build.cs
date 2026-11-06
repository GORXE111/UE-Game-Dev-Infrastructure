using UnrealBuildTool;

public class ProfileSample : ModuleRules
{
    public ProfileSample(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PrivateDependencyModuleNames.AddRange(new[] { "Core", "CoreUObject", "Engine", "GameplayTags", "Json" });
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicSystemLibraries.Add("bcrypt.lib");
        }
        if (Target.Platform == UnrealTargetPlatform.Android)
        {
            PrivateDependencyModuleNames.Add("PakFile");
        }
    }
}
