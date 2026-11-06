#pragma once

#include "CoreMinimal.h"
#include "GameFramework/SaveGame.h"
#include "ProfileReleaseSample.generated.h"

UCLASS()
class UProfileReleaseSave : public USaveGame
{
    GENERATED_BODY()

public:
    UPROPERTY(SaveGame)
    int32 SchemaVersion = 1;

    UPROPERTY(SaveGame)
    int32 Progress = 0;
};

// Without a boot ticket, only the native/content pair is checked.
uint8 CheckProfileReleaseSample(bool bManagedBoot, const FString& TicketPath);
