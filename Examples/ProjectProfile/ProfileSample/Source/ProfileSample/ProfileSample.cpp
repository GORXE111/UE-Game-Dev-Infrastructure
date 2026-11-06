#include "ProfileConfigRows.h"
#include "ProfileReleaseSample.h"

#include "Engine/DataTable.h"
#include "Engine/Engine.h"
#include "Engine/World.h"
#include "GameplayTagsManager.h"
#include "HAL/PlatformMisc.h"
#include "Misc/CommandLine.h"
#include "Misc/CoreDelegates.h"
#include "Misc/OutputDeviceRedirector.h"
#include "Misc/Parse.h"
#include "Misc/Paths.h"
#include "Modules/ModuleManager.h"
#include "UObject/Package.h"

class FProfileSampleModule final : public FDefaultGameModuleImpl
{
public:
    void StartupModule() override
    {
        bManagedBoot = FParse::Value(FCommandLine::Get(), TEXT("SampleGameReleaseTicket="), ReleaseTicket, false);
        if (bManagedBoot || FParse::Param(FCommandLine::Get(), TEXT("AdoptionProfileSmoke")))
        {
            EndFrame = FCoreDelegates::OnEndFrame.AddRaw(this, &FProfileSampleModule::CheckGame);
        }
        if (FParse::Param(FCommandLine::Get(), TEXT("AdoptionSessionSmoke")))
        {
            PostEngineInit = FCoreDelegates::GetOnPostEngineInit().AddRaw(this, &FProfileSampleModule::WatchSession);
        }
    }

    void ShutdownModule() override
    {
        FCoreDelegates::OnEndFrame.Remove(EndFrame);
        FCoreDelegates::GetOnPostEngineInit().Remove(PostEngineInit);
        if (NetworkFailure.IsValid() && GEngine)
        {
            GEngine->OnNetworkFailure().Remove(NetworkFailure);
        }
    }

private:
    void WatchSession()
    {
        NetworkFailure = GEngine->OnNetworkFailure().AddRaw(this, &FProfileSampleModule::CheckSessionFailure);
    }

    void CheckSessionFailure(UWorld*, UNetDriver*, ENetworkFailure::Type FailureType, const FString& Error)
    {
        if (FailureType == ENetworkFailure::PendingConnectionFailure &&
            Error.Equals(TEXT("ADOPTION_CONFIG_MISMATCH"), ESearchCase::CaseSensitive))
        {
            UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_SESSION_CLIENT_REJECTED"));
            FPlatformMisc::RequestExit(false);
            return;
        }

        UE_LOG(LogTemp, Error, TEXT("Unexpected adoption session failure: %s"), *Error);
        FPlatformMisc::RequestExitWithStatus(true, 1);
    }

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
                if (FPaths::FileExists(FPaths::ProjectContentDir() / TEXT("GeneratedConfig/shared-config.sha256")))
                {
                    const UDataTable* Enemies = LoadObject<UDataTable>(nullptr, TEXT("/Game/Generated/DT_Enemies.DT_Enemies"));
                    const UDataTable* Waves = LoadObject<UDataTable>(nullptr, TEXT("/Game/Generated/DT_Waves.DT_Waves"));
                    const FProfileEnemyRow* Enemy = Enemies ? Enemies->FindRow<FProfileEnemyRow>(TEXT("Scout"), TEXT("ProfileSmoke")) : nullptr;
                    const FProfileWaveRow* Wave = Waves ? Waves->FindRow<FProfileWaveRow>(TEXT("Opening"), TEXT("ProfileSmoke")) : nullptr;
                    if (!Enemy || Enemy->Health != 35 || !Wave || Wave->EnemyId != TEXT("Scout") || Wave->Count != 2)
                    {
                        UE_LOG(LogTemp, Error, TEXT("Cooked gameplay tables did not contain the expected enemy and wave"));
                        FPlatformMisc::RequestExitWithStatus(true, 1);
                        return;
                    }
                    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_CONFIG_TABLES_READY enemy=Scout health=35 wave=Opening count=2"));
                }
                const uint8 ReleaseResult = CheckProfileReleaseSample(bManagedBoot, ReleaseTicket);
                if (ReleaseResult != 0)
                {
                    GLog->FlushThreadedLogs();
#if PLATFORM_ANDROID
                    FPlatformMisc::RequestExit(true);
#else
                    FPlatformMisc::RequestExitWithStatus(true, ReleaseResult);
#endif
                    return;
                }
                UE_LOG(LogTemp, Display, TEXT("UE_PROJECT_PROFILE_READY map=/Engine/Maps/Entry table=GameplayTags rows=2"));
#if PLATFORM_ANDROID
                if (bManagedBoot)
                {
                    return; // Keep the Java download worker alive after the confirmed game starts.
                }
#endif
                FPlatformMisc::RequestExit(false);
                return;
            }
        }
    }

    FDelegateHandle EndFrame;
    FDelegateHandle PostEngineInit;
    FDelegateHandle NetworkFailure;
    FString ReleaseTicket;
    bool bManagedBoot = false;
};

IMPLEMENT_PRIMARY_GAME_MODULE(FProfileSampleModule, ProfileSample, "ProfileSample");
