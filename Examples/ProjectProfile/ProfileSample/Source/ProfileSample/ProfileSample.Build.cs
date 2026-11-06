using UnrealBuildTool;

public class ProfileSample : ModuleRules
{
    public ProfileSample(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PrivateDependencyModuleNames.AddRange(new[] { "Core", "CoreUObject", "Engine", "GameplayTags" });
    }
}
