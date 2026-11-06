using UnrealBuildTool;

public class ProfileSampleTarget : TargetRules
{
    public ProfileSampleTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Game;
        DefaultBuildSettings = BuildSettingsVersion.Latest;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        ExtraModuleNames.Add("ProfileSample");
    }
}
