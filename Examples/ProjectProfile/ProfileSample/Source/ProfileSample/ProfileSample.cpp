#include "Engine/DataTable.h"
#include "Engine/Engine.h"
#include "Engine/World.h"
#include "GameplayTagsManager.h"
#include "HAL/PlatformMisc.h"
#include "Misc/CommandLine.h"
#include "Misc/CoreDelegates.h"
#include "Misc/Parse.h"
#include "Modules/ModuleManager.h"
#include "UObject/Package.h"

class FProfileSampleModule final : public FDefaultGameModuleImpl
{
public:
    void StartupModule() override
    {
        if (FParse::Param(FCommandLine::Get(), TEXT("AdoptionProfileSmoke")))
        {
            EndFrame = FCoreDelegates::OnEndFrame.AddRaw(this, &FProfileSampleModule::CheckGame);
        }
    }

    void ShutdownModule() override
    {
        FCoreDelegates::OnEndFrame.Remove(EndFrame);
    }

private:
    void CheckGame()
    {
        if (!GEngine)
        {
            return;
        }
        for (const FWorldContext& Context : GEngine->GetWorldContexts())
        {
            const UWorld* World = Context.World();
            if (Context.WorldType == EWorldType::Game && World && World->HasBegunPlay() &&
                World->GetOutermost()->GetName() == TEXT("/Engine/Maps/Entry"))
            {
                FCoreDelegates::OnEndFrame.Remove(EndFrame);
                const UDataTable* Table = LoadObject<UDataTable>(nullptr,
                    TEXT("/Game/Generated/DT_GameplayTags.DT_GameplayTags"));
                const FGameplayTagTableRow* Guard = Table ? Table->FindRow<FGameplayTagTableRow>(TEXT("EnemyGuard"), TEXT("ProfileSmoke")) : nullptr;
                const FGameplayTagTableRow* Scout = Table ? Table->FindRow<FGameplayTagTableRow>(TEXT("EnemyScout"), TEXT("ProfileSmoke")) : nullptr;
                if (!Guard || !Scout || Table->GetRowNames().Num() != 2 ||
                    Guard->Tag != TEXT("Example.Enemy.Guard") || Scout->Tag != TEXT("Example.Enemy.Scout") ||
                    Guard->DevComment != TEXT("守卫标签") || Scout->DevComment != TEXT("侦察兵标签"))
                {
                    UE_LOG(LogTemp, Error, TEXT("Generated table did not contain the expected cooked rows"));
                    FPlatformMisc::RequestExitWithStatus(true, 1);
                    return;
                }
                UE_LOG(LogTemp, Display, TEXT("UE_PROJECT_PROFILE_READY map=/Engine/Maps/Entry table=GameplayTags rows=2"));
                FPlatformMisc::RequestExit(false);
                return;
            }
        }
    }

    FDelegateHandle EndFrame;
};

IMPLEMENT_PRIMARY_GAME_MODULE(FProfileSampleModule, ProfileSample, "ProfileSample");
