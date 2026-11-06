#pragma once

#include "Containers/UnrealString.h"

struct FProfileDedicatedConfigSummary
{
    int32 EnemyCount = 0;
    int32 WaveCount = 0;
    int64 WaveAiBudget = 0;
};

bool LoadProfileDedicatedConfig(const FString& SharedConfigId, FProfileDedicatedConfigSummary& Summary, FString& Error);
