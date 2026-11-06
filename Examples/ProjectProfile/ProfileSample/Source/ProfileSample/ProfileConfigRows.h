#pragma once

#include "Engine/DataTable.h"
#include "ProfileConfigRows.generated.h"

USTRUCT()
struct FProfileEnemyRow : public FTableRowBase
{
    GENERATED_BODY()

    UPROPERTY()
    int32 Health = 0;

    UPROPERTY()
    FString DisplayName;
};

USTRUCT()
struct FProfileWaveRow : public FTableRowBase
{
    GENERATED_BODY()

    UPROPERTY()
    FName EnemyId;

    UPROPERTY()
    int32 Count = 0;
};
