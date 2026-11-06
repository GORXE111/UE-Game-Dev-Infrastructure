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

#if PLATFORM_ANDROID
#include "Android/AndroidJavaEnv.h"
#include "HAL/PlatformFileManager.h"
#include "IPlatformFilePak.h"
#include "Misc/CommandLine.h"
#include "Misc/Parse.h"
#include <dlfcn.h>
#endif

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
        FString PayloadRoot;
        FString UserRoot;
        FString AckPath;
        int64 ReleaseId = 0;
    };

    bool ParseJson(const FString& Raw, TSharedPtr<FJsonObject>& Json)
    {
        return Raw.Len() <= MaxJsonBytes &&
            FJsonSerializer::Deserialize(TJsonReaderFactory<>::Create(Raw), Json) && Json.IsValid();
    }

    bool ReadJson(const FString& Path, TSharedPtr<FJsonObject>& Json)
    {
        const int64 Size = IFileManager::Get().FileSize(*Path);
        FString Raw;
        return Size > 0 && Size <= MaxJsonBytes && FFileHelper::LoadFileToString(Raw, *Path) && ParseJson(Raw, Json);
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

#if PLATFORM_ANDROID
    template <typename FCall>
    bool CallReleasePlayer(const char* Name, const char* Signature, FCall Call)
    {
        JNIEnv* Env = AndroidJavaEnv::GetJavaEnv();
        if (!Env)
        {
            return false;
        }
        jclass Class = AndroidJavaEnv::FindJavaClass("com/example/samplegame/update/ReleasePlayer");
        if (Env->ExceptionCheck())
        {
            Env->ExceptionClear();
            return false;
        }
        if (!Class)
        {
            return false;
        }
        jmethodID Method = Env->GetStaticMethodID(Class, Name, Signature);
        const bool bCalled = Method && !Env->ExceptionCheck() && Call(Env, Class, Method);
        const bool bThrew = Env->ExceptionCheck();
        if (bThrew)
        {
            Env->ExceptionClear();
        }
        Env->DeleteLocalRef(Class);
        return bCalled && !bThrew;
    }

    bool ReadTicketJson(const FString&, TSharedPtr<FJsonObject>& Json)
    {
        FString Raw;
        const bool bRead = CallReleasePlayer("selectionJson", "()Ljava/lang/String;",
            [&Raw](JNIEnv* Env, jclass Class, jmethodID Method)
            {
                jstring Selection = static_cast<jstring>(Env->CallStaticObjectMethod(Class, Method));
                if (!Selection || Env->ExceptionCheck())
                {
                    return false;
                }
                if (Env->GetStringLength(Selection) > MaxJsonBytes)
                {
                    Env->DeleteLocalRef(Selection);
                    return false;
                }
                Raw = FJavaHelper::FStringFromLocalRef(Env, Selection);
                return true;
            });
        double Format = 0;
        return bRead && ParseJson(Raw, Json) && Json->Values.Num() == 9 &&
            Json->TryGetNumberField(TEXT("format"), Format) && Format == 1;
    }

    bool CheckAndroidPayload(const FReleaseTicket& Ticket, const FString& MarkerPath)
    {
        Dl_info Library{};
        if (!dladdr(&NativeMarker, &Library) || !Library.dli_fname ||
            !FPaths::IsSamePath(UTF8_TO_TCHAR(Library.dli_fname), Ticket.PayloadRoot / TEXT("libUnreal.so")))
        {
            return false;
        }

        // GameActivity accepts these arguments only from the prepared, verified Java selection.
        const FString PakDirectory = Ticket.PayloadRoot / TEXT("Content/Paks");
        FString SelectedDirectory;
        FString SelectedNames;
        if (!FParse::Value(FCommandLine::Get(), TEXT("-pakdir="), SelectedDirectory, false) ||
            !IsSameDirectory(SelectedDirectory, PakDirectory) ||
            !FParse::Value(FCommandLine::Get(), TEXT("-paklist="), SelectedNames))
        {
            return false;
        }
        TArray<FString> Names;
        SelectedNames.ParseIntoArray(Names, TEXT("+"), false);
        if (Names.IsEmpty() || Names.Num() > 64)
        {
            return false;
        }

        FPakPlatformFile* PakFile = static_cast<FPakPlatformFile*>(
            FPlatformFileManager::Get().FindPlatformFile(FPakPlatformFile::GetTypeName()));
        if (!PakFile)
        {
            return false;
        }
        TArray<FString> Mounted;
        PakFile->GetMountedPakFilenames(Mounted);
        if (Mounted.Num() != Names.Num())
        {
            return false;
        }
        const FString Prefix = FString::Printf(TEXT("r%lld_"), Ticket.ReleaseId);
        for (const FString& Name : Names)
        {
            if (!Name.StartsWith(Prefix, ESearchCase::CaseSensitive) || FPaths::GetCleanFilename(Name) != Name)
            {
                return false;
            }
            const FString Expected = PakDirectory / (Name + TEXT(".pak"));
            if (Mounted.RemoveAll([&Expected](const FString& Path) { return FPaths::IsSamePath(Path, Expected); }) != 1)
            {
                return false;
            }
        }

        TRefCountPtr<FPakFile> MarkerPak;
        if (!PakFile->FindFileInPakFiles(*MarkerPath, &MarkerPak) || !MarkerPak ||
            !IsSameDirectory(FPaths::GetPath(MarkerPak->GetFilename()), PakDirectory))
        {
            return false;
        }
        UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_ANDROID_PAYLOAD_READY release=%lld paks=%d"),
            Ticket.ReleaseId, Names.Num());
        return true;
    }
#else
    bool ReadTicketJson(const FString& Path, TSharedPtr<FJsonObject>& Json)
    {
        return ReadJson(Path, Json) && Json->Values.Num() == 8;
    }
#endif

    bool ReadTicket(const FString& Path, FReleaseTicket& Ticket)
    {
        TSharedPtr<FJsonObject> Json;
        double ReleaseId = 0;
        double Schema = 0;
        if (Path.IsEmpty() || FPaths::IsRelative(Path) || FPaths::GetCleanFilename(Path) != TEXT("ticket.json") ||
            !ReadTicketJson(Path, Json) ||
            !Json->TryGetStringField(TEXT("attemptId"), Ticket.AttemptId) || !IsLowerHex(Ticket.AttemptId, 32) ||
            !Json->TryGetStringField(TEXT("manifestSha256"), Ticket.ManifestSha256) || !IsLowerHex(Ticket.ManifestSha256, 64) ||
            !Json->TryGetStringField(TEXT("buildId"), Ticket.BuildId) || !IsLowerHex(Ticket.BuildId, 64) ||
            !Json->TryGetNumberField(TEXT("releaseId"), ReleaseId) ||
            !(ReleaseId >= 1 && ReleaseId <= static_cast<double>(MaxExactJsonInteger)) ||
            !Json->TryGetNumberField(TEXT("saveSchema"), Schema) || Schema != SaveSchema ||
            !Json->TryGetStringField(TEXT("payloadRoot"), Ticket.PayloadRoot) || FPaths::IsRelative(Ticket.PayloadRoot) ||
            !Json->TryGetStringField(TEXT("userRoot"), Ticket.UserRoot) || FPaths::IsRelative(Ticket.UserRoot) ||
            !Json->TryGetStringField(TEXT("ackPath"), Ticket.AckPath) || FPaths::IsRelative(Ticket.AckPath))
        {
            return false;
        }
        Ticket.ReleaseId = static_cast<int64>(ReleaseId);
        return static_cast<double>(Ticket.ReleaseId) == ReleaseId &&
            FPaths::IsSamePath(Ticket.AckPath, FPaths::GetPath(Path) / TEXT("health.json")) &&
#if !PLATFORM_ANDROID
            IsSameDirectory(FPaths::ProjectDir(), Ticket.PayloadRoot / TEXT("ProfileSample")) &&
#endif
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

    bool ConfirmHealth(const FReleaseTicket& Ticket)
    {
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
        if (!Writer->Close())
        {
            return false;
        }
#if PLATFORM_ANDROID
        return CallReleasePlayer("acknowledge", "(Ljava/lang/String;)Z",
            [&Raw](JNIEnv* Env, jclass Class, jmethodID Method)
            {
                const auto Acknowledgement = FJavaHelper::ToJavaString(Env, Raw);
                return *Acknowledgement && Env->CallStaticBooleanMethod(Class, Method, *Acknowledgement) == JNI_TRUE;
            });
#else
        IFileManager& Files = IFileManager::Get();
        const FString Temporary = Ticket.AckPath + TEXT(".tmp");
        return !Files.FileExists(*Ticket.AckPath) && !Files.FileExists(*Temporary) &&
            FFileHelper::SaveStringToFile(Raw, *Temporary, FFileHelper::EEncodingOptions::ForceUTF8WithoutBOM) &&
            Files.Move(*Ticket.AckPath, *Temporary, false);
#endif
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
    if (!ReadTicket(TicketPath, Ticket))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Invalid boot ticket"));
        return 1;
    }
#if PLATFORM_ANDROID
    if (!CheckAndroidPayload(Ticket, MarkerPath))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Loaded library or mounted PAKs differ from the Android selection"));
        return 1;
    }
#endif
    if (!CheckSave(bBaseline, bFault))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Invalid save generation"));
        return 1;
    }
    if (bFault)
    {
        UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_FAULT_BEFORE_HEALTH"));
        return 23;
    }
    if (!ConfirmHealth(Ticket))
    {
        UE_LOG(LogTemp, Error, TEXT("UE_ADOPTION_RELEASE_REJECTED Could not publish boot acknowledgement"));
        return 1;
    }
    UE_LOG(LogTemp, Display, TEXT("UE_ADOPTION_RELEASE_HEALTH release=%lld native=%s"), Ticket.ReleaseId, NativeMarker);
    return 0;
}
