#pragma once

#include "CoreMinimal.h"
#include "GameFramework/GameModeBase.h"
#include "GameFramework/PlayerController.h"

#include "ProfileSessionMode.generated.h"

UCLASS()
class AProfileSessionController final : public APlayerController
{
    GENERATED_BODY()

public:
    UFUNCTION(Client, Reliable)
    void ClientConfirmProfileSession(const FString& SharedConfigId);
};

UCLASS()
class AProfileSessionMode final : public AGameModeBase
{
    GENERATED_BODY()

public:
    AProfileSessionMode();

    void InitGame(const FString& MapName, const FString& Options, FString& ErrorMessage) override;
    void StartPlay() override;
    void PreLogin(const FString& Options, const FString& Address, const FUniqueNetIdRepl& UniqueId,
        FString& ErrorMessage) override;
    void PostLogin(APlayerController* NewPlayer) override;

private:
    FString SharedConfigId;
};
