using UnrealBuildTool;

public class ProfileSampleEditorTarget : TargetRules
{
    public ProfileSampleEditorTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Editor;
        DefaultBuildSettings = BuildSettingsVersion.Latest;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        ExtraModuleNames.Add("ProfileSample");
    }
}
