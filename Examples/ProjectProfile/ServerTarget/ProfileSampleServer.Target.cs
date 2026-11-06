using UnrealBuildTool;

public class ProfileSampleServerTarget : TargetRules
{
    public ProfileSampleServerTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Server;
        BuildEnvironment = TargetBuildEnvironment.Unique;
        DefaultBuildSettings = BuildSettingsVersion.Latest;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        ExtraModuleNames.Add("ProfileSample");
    }
}
