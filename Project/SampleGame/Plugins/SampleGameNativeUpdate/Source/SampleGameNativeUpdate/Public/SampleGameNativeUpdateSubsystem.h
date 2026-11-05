#pragma once

#include "CoreMinimal.h"
#include "Containers/Ticker.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "SampleGameNativeUpdateSubsystem.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FSampleGameNativeUpdateStatusEvent, const FString&, StatusJson);

/** Android updates are prepared in the background and applied before UE starts in a new process. */
UCLASS()
class SAMPLEGAMENATIVEUPDATE_API USampleGameNativeUpdateSubsystem : public UGameInstanceSubsystem
{
    GENERATED_BODY()

public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, Category = "SampleGame|Native Update")
    void CheckForNativeUpdate();

    UFUNCTION(BlueprintPure, Category = "SampleGame|Native Update")
    FString GetStatusJson() const { return StatusJson; }

    UFUNCTION(BlueprintPure, Category = "SampleGame|Native Update")
    bool IsRestartRequired() const { return bRestartRequired; }

    /** Planned content restarts must wait for the existing native startup health check. */
    bool IsStartupPending() const { return bStartupPending; }
    bool HasStartupStatus() const { return bStartupStatusKnown; }

    UPROPERTY(BlueprintAssignable, Category = "SampleGame|Native Update")
    FSampleGameNativeUpdateStatusEvent OnStatusChanged;

private:
    friend struct FSampleGameNativeStartupTestAccess;
    bool TickStatus(float DeltaSeconds);
    void RefreshStatus();
    FTSTicker::FDelegateHandle TickerHandle;
    TWeakObjectPtr<UWorld> StableWorld;
    double StableWorldSince = 0.0;
    double NextConfirmationTime = 0.0;
    bool bAutomaticCheckStarted = false;
    bool bStartupConfirmed = false;
    bool bStartupPending = false;
    bool bStartupStatusKnown = false;
    bool bRestartRequired = false;
    FString StatusJson = TEXT("{\"enabled\":false,\"state\":\"UnsupportedPlatform\",\"restartRequired\":false}");
    FString LastState;
};
