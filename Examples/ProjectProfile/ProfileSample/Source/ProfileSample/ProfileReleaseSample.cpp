#include "ProfileReleaseSample.h"

#include "Dom/JsonObject.h"
#include "HAL/FileManager.h"
#include "HAL/PlatformProcess.h"
#include "Kismet/GameplayStatics.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "ProfileReleaseVariant.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"
#include "Serialization/JsonWriter.h"

namespace
{
    constexpr int64 MaxExactJsonInteger = (int64{1} << 53) - 1;
    constexpr int64 MaxJsonBytes = 8192;
    constexpr int32 OriginalProgress = 731;
    constexpr int32 FaultProgress = 997;
    constexpr int32 SaveSchema = 1;
    const TCHAR* SaveSlot = TEXT("AdoptionRelease");
    const TCHAR* NativeMarker = ADOPTION_RELEASE_NATIVE_MARKER;

    struct FReleaseTicket
    {
        FString AttemptId;
        FString ManifestSha256;
        FString BuildId;
        FString UserRoot;
        FString AckPath;
        int64 ReleaseId = 0;
    };

    bool ReadJson(const FString& Path, TSharedPtr<FJsonObject>& Json)
    {
        const int64 Size = IFileManager::Get().FileSize(*Path);
        FString Raw;
        return Size > 0 && Size <= MaxJsonBytes && FFileHelper::LoadFileToString(Raw, *Path) &&
            Raw.Len() <= MaxJsonBytes && FJsonSerializer::Deserialize(TJsonReaderFactory<>::Create(Raw), Json) &&
            Json.IsValid();
    }

    bool IsLowerHex(const FString& Value, int32 Length)
    {
        if (Value.Len() != Length)
        {
            return false;
        }
        for (const TCHAR Digit : Value)
        {
            if (!(Digit >= '0' && Digit <= '9') && !(Digit >= 'a' && Digit <= 'f'))
            {
                return false;
            }
        }
        return true;
    }

    bool IsSameDirectory(FString First, FString Second)
    {
        FPaths::NormalizeDirectoryName(First);
        FPaths::NormalizeDirectoryName(Second);
        return FPaths::IsSamePath(First, Second);
    }

    bool ReadTicket(const FString& Path, FReleaseTicket& Ticket)
    {
        TSharedPtr<FJsonObject> Json;
        FString PayloadRoot;
        double ReleaseId = 0;
        double Schema = 0;
        if (Path.IsEmpty() || FPaths::IsRelative(Path) || FPaths::GetCleanFilename(Path) != TEXT("ticket.json") ||
            !ReadJson(Path, Json) || Json->Values.Num() != 8 ||
            !Json->TryGetStringField(TEXT("attemptId"), Ticket.AttemptId) || !IsLowerHex(Ticket.AttemptId, 32) ||
            !Json->TryGetStringField(TEXT("manifestSha256"), Ticket.ManifestSha256) || !IsLowerHex(Ticket.ManifestSha256, 64) ||
            !Json->TryGetStringField(TEXT("buildId"), Ticket.BuildId) || !IsLowerHex(Ticket.BuildId, 64) ||
            !Json->TryGetNumberField(TEXT("releaseId"), ReleaseId) ||
            !(ReleaseId >= 1 && ReleaseId <= static_cast<double>(MaxExactJsonInteger)) ||
            !Json->TryGetNumberField(TEXT("saveSchema"), Schema) || Schema != SaveSchema ||
            !Json->TryGetStringField(TEXT("payloadRoot"), PayloadRoot) || FPaths::IsRelative(PayloadRoot) ||
            !Json->TryGetStringField(TEXT("userRoot"), Ticket.UserRoot) || FPaths::IsRelative(Ticket.UserRoot) ||
            !Json->TryGetStringField(TEXT("ackPath"), Ticket.AckPath) || FPaths::IsRelative(Ticket.AckPath))
        {
            return false;
        }
        Ticket.ReleaseId = static_cast<int64>(ReleaseId);
        return static_cast<double>(Ticket.ReleaseId) == ReleaseId &&
            FPaths::IsSamePath(Ticket.AckPath, FPaths::GetPath(Path) / TEXT("health.json")) &&
            IsSameDirectory(FPaths::ProjectDir(), PayloadRoot / TEXT("ProfileSample")) &&
            IsSameDirectory(FPaths::ProjectUserDir(), Ticket.UserRoot) &&
            IsSameDirectory(FPaths::ProjectSavedDir(), Ticket.UserRoot / TEXT("Saved"));
    }

    bool CheckSave(bool bBaseline, bool bFault)
    {
        const bool bHasSave = UGameplayStatics::DoesSaveGameExist(SaveSlot, 0);
        UProfileReleaseSave* Save = bHasSave
            ? Cast<UProfileReleaseSave>(UGameplayStatics::LoadGameFromSlot(SaveSlot, 0))
            : nullptr;
        if (bHasSave && (!Save || Save->SchemaVersion != SaveSchema || Save->Progress != OriginalProgress))
        {
            return false;
        }
        if (!bHasSave)
        {
            if (!bBaseline)
            {
                return false;
            }
            Save = Cast<UProfileReleaseSave>(UGameplayStatics::CreateSaveGameObject(UProfileReleaseSave::StaticClass()));
            if (!Save)
            {
                return false;
            }
        }

        const int32 Progress = bFault ? FaultProgress : OriginalProgress;
        if (!bHasSave || bFault)
        {
            Save->Progress = Progress;
            if (!UGameplayStatics::SaveGameToSlot(Save, SaveSlot, 0))
            {
                return false;
            }
            Save = Cast<UProfileReleaseSave>(UGameplayStatics::LoadGameFromSlot(SaveSlot, 0));
            if (!Save || Save->SchemaVersion != SaveSchema || Save->Progress != Progress)
            {
                return false;
            }
        }

        UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_SAVE_READY native=%s progress=%d"), NativeMarker, Save->Progress);
        return true;
    }

    bool WriteHealth(const FReleaseTicket& Ticket)
    {
        IFileManager& Files = IFileManager::Get();
        const FString Temporary = Ticket.AckPath + TEXT(".tmp");
        if (Files.FileExists(*Ticket.AckPath) || Files.FileExists(*Temporary))
        {
            return false;
        }

        FString Raw;
        const TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&Raw);
        Writer->WriteObjectStart();
        Writer->WriteValue(TEXT("format"), 1);
        Writer->WriteValue(TEXT("attemptId"), Ticket.AttemptId);
        Writer->WriteValue(TEXT("releaseId"), Ticket.ReleaseId);
        Writer->WriteValue(TEXT("manifestSha256"), Ticket.ManifestSha256);
        Writer->WriteValue(TEXT("buildId"), Ticket.BuildId);
        Writer->WriteValue(TEXT("saveSchema"), SaveSchema);
        Writer->WriteValue(TEXT("pid"), FPlatformProcess::GetCurrentProcessId());
        Writer->WriteValue(TEXT("userRoot"), Ticket.UserRoot);
        Writer->WriteValue(TEXT("luaVersion"), FString(TEXT("not-applicable")));
        Writer->WriteObjectEnd();
        return Writer->Close() && FFileHelper::SaveStringToFile(Raw, *Temporary, FFileHelper::EEncodingOptions::ForceUTF8WithoutBOM) &&
            Files.Move(*Ticket.AckPath, *Temporary, false);
    }
}

uint8 CheckProfileReleaseSample(bool bManagedBoot, const FString& TicketPath)
{
    const bool bBaseline = FCString::Strcmp(NativeMarker, TEXT("baseline")) == 0;
    const bool bCandidate = FCString::Strcmp(NativeMarker, TEXT("candidate")) == 0;
    const bool bFault = FCString::Strcmp(NativeMarker, TEXT("fault")) == 0;
    const FString MarkerPath = FPaths::ProjectContentDir() / TEXT("ReleaseProof/release-sample.json");
    TSharedPtr<FJsonObject> Marker;
    double Format = 0;
    FString ContentMarker;
    if ((!bBaseline && !bCandidate && !bFault) ||
        !ReadJson(MarkerPath, Marker) || Marker->Values.Num() != 2 ||
        !Marker->TryGetNumberField(TEXT("format"), Format) || Format != 1 ||
        !Marker->TryGetStringField(TEXT("nativeMarker"), ContentMarker) || !ContentMarker.Equals(NativeMarker, ESearchCase::CaseSensitive))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Native executable and cooked release marker differ"));
        return 1;
    }
    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_PAIR_READY native=%s content=%s"), NativeMarker, *ContentMarker);
    if (!bManagedBoot)
    {
        return 0;
    }

    FReleaseTicket Ticket;
    if (!ReadTicket(TicketPath, Ticket) || !CheckSave(bBaseline, bFault))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Invalid boot ticket or save generation"));
        return 1;
    }
    if (bFault)
    {
        UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_FAULT_BEFORE_HEALTH"));
        return 23;
    }
    if (!WriteHealth(Ticket))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Could not publish boot acknowledgement"));
        return 1;
    }
    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_HEALTH release=%lld native=%s"), Ticket.ReleaseId, NativeMarker);
    return 0;
}
