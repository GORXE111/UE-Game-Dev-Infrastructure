#include "ProfileSessionMode.h"

#include "Engine/World.h"
#include "HAL/PlatformMisc.h"
#include "Kismet/GameplayStatics.h"
#include "Misc/CommandLine.h"
#include "Misc/FileHelper.h"
#include "Misc/Parse.h"
#include "Misc/Paths.h"
#include "UObject/Package.h"

namespace
{
    bool LoadSharedConfigId(FString& ConfigId)
    {
        const FString Path = FPaths::ProjectContentDir() / TEXT("GeneratedConfig/shared-config.sha256");
        if (!FFileHelper::LoadFileToString(ConfigId, *Path))
        {
            return false;
        }

        ConfigId.TrimStartAndEndInline();
        if (ConfigId.Len() != 64)
        {
            return false;
        }
        for (const TCHAR Digit : ConfigId)
        {
            if (!(Digit >= '0' && Digit <= '9') && !(Digit >= 'a' && Digit <= 'f'))
            {
                return false;
            }
        }
        return true;
    }
}

AProfileSessionMode::AProfileSessionMode()
{
    PlayerControllerClass = AProfileSessionController::StaticClass();
}

void AProfileSessionMode::InitGame(const FString& MapName, const FString& Options, FString& ErrorMessage)
{
    Super::InitGame(MapName, Options, ErrorMessage);
    if (!LoadSharedConfigId(SharedConfigId))
    {
        SharedConfigId.Reset();
        ErrorMessage = TEXT("ADOPTION_CONFIG_UNAVAILABLE");
    }
}

void AProfileSessionMode::StartPlay()
{
    Super::StartPlay();
    const ENetMode NetMode = GetNetMode();
    if (SharedConfigId.IsEmpty() || (NetMode != NM_ListenServer && NetMode != NM_DedicatedServer))
    {
        UE_LOG(LogTemp, Error, TEXT("Adoption session host did not start with a valid cooked configuration and net driver"));
        FPlatformMisc::RequestExitWithStatus(true, 1);
        return;
    }
    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_SESSION_SERVER_READY shared=%s"), *SharedConfigId);
}

void AProfileSessionMode::PreLogin(const FString& Options, const FString& Address, const FUniqueNetIdRepl& UniqueId,
    FString& ErrorMessage)
{
    Super::PreLogin(Options, Address, UniqueId, ErrorMessage);
    if (ErrorMessage.IsEmpty() && (SharedConfigId.IsEmpty() ||
        !UGameplayStatics::ParseOption(Options, TEXT("AdoptionConfigId")).Equals(SharedConfigId, ESearchCase::CaseSensitive)))
    {
        ErrorMessage = TEXT("ADOPTION_CONFIG_MISMATCH");
    }
}

void AProfileSessionMode::PostLogin(APlayerController* NewPlayer)
{
    Super::PostLogin(NewPlayer);
    if (AProfileSessionController* Controller = Cast<AProfileSessionController>(NewPlayer);
        Controller && Controller->GetNetConnection() && !Controller->IsLocalController())
    {
        Controller->ClientConfirmProfileSession(SharedConfigId);
    }
}

void AProfileSessionController::ClientConfirmProfileSession_Implementation(const FString& SharedConfigId)
{
    if (!FParse::Param(FCommandLine::Get(), TEXT("AdoptionSessionSmoke")) ||
        GetNetMode() != NM_Client || !IsLocalController())
    {
        return;
    }

    FString LocalConfigId;
    const UWorld* World = GetWorld();
    if (!World || World->GetOutermost()->GetName() != TEXT("/Engine/Maps/Entry") ||
        !LoadSharedConfigId(LocalConfigId) || !LocalConfigId.Equals(SharedConfigId, ESearchCase::CaseSensitive))
    {
        UE_LOG(LogTemp, Error, TEXT("Adoption session client received an unexpected map or shared configuration"));
        FPlatformMisc::RequestExitWithStatus(true, 1);
        return;
    }

    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_SESSION_CLIENT_CONNECTED shared=%s"), *LocalConfigId);
    FPlatformMisc::RequestExit(false);
}
