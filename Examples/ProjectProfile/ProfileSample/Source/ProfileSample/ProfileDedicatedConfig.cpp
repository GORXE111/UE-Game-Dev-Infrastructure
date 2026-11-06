#include "ProfileDedicatedConfig.h"

#include "Containers/StringConv.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "HAL/FileManager.h"
#include "Misc/CommandLine.h"
#include "Misc/Parse.h"
#include "Misc/Paths.h"
#include "Serialization/Archive.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"

#if PLATFORM_WINDOWS
#include "Windows/WindowsHWrapper.h"
#include "Windows/AllowWindowsPlatformTypes.h"
#include <bcrypt.h>
#include "Windows/HideWindowsPlatformTypes.h"
#endif

namespace
{
    constexpr int32 MaxManifestBytes = 64 * 1024;
    constexpr int32 MaxTableBytes = 4 * 1024 * 1024;
    constexpr int32 MaxFiles = 64;
    constexpr int32 MaxRows = 100000;

    bool IsLowerSha256(const FString& Value)
    {
        if (Value.Len() != 64)
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

    bool IsAsciiLetter(TCHAR Character)
    {
        return (Character >= 'A' && Character <= 'Z') || (Character >= 'a' && Character <= 'z');
    }

    bool IsTableIdentifier(FStringView Identifier)
    {
        if (Identifier.IsEmpty() || Identifier.Len() > 63 || (!IsAsciiLetter(Identifier[0]) && Identifier[0] != '_'))
        {
            return false;
        }
        for (const TCHAR Character : Identifier)
        {
            if (!IsAsciiLetter(Character) && !(Character >= '0' && Character <= '9') && Character != '_')
            {
                return false;
            }
        }
        return true;
    }

    bool ReadConfigBytes(const FString& Path, int32 Limit, TArray<uint8>& Bytes)
    {
        TUniquePtr<FArchive> Reader(IFileManager::Get().CreateFileReader(*Path, FILEREAD_Silent));
        if (!Reader || Reader->TotalSize() <= 0 || Reader->TotalSize() > Limit)
        {
            return false;
        }
        Bytes.SetNumUninitialized(static_cast<int32>(Reader->TotalSize()));
        Reader->Serialize(Bytes.GetData(), Bytes.Num());
        return Reader->Close() && !Reader->IsError();
    }

    bool MatchesSha256(TArray<uint8>& Bytes, const FString& Expected)
    {
#if PLATFORM_WINDOWS
        BCRYPT_ALG_HANDLE Algorithm = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        {
            return false;
        }
        uint8 Digest[32];
        const bool bHasDigest = BCRYPT_SUCCESS(BCryptHash(Algorithm, nullptr, 0, Bytes.GetData(),
            static_cast<ULONG>(Bytes.Num()), Digest, static_cast<ULONG>(sizeof(Digest))));
        BCryptCloseAlgorithmProvider(Algorithm, 0);
        return bHasDigest && BytesToHexLower(Digest, UE_ARRAY_COUNT(Digest)).Equals(Expected, ESearchCase::CaseSensitive);
#else
        return false;
#endif
    }

    TSharedRef<TJsonReader<>> MakeJsonReader(const TArray<uint8>& Bytes)
    {
        const FUTF8ToTCHAR Utf8(reinterpret_cast<const UTF8CHAR*>(Bytes.GetData()), Bytes.Num());
        return TJsonReaderFactory<>::Create(FString(Utf8.Length(), Utf8.Get()));
    }

    bool ReadString(const FJsonObject& Object, FStringView Field, FString& Out)
    {
        const TSharedPtr<FJsonValue> Value = Object.TryGetField(Field);
        return Value.IsValid() && Value->Type == EJson::String && Value->TryGetString(Out);
    }

    bool ReadInt(const FJsonObject& Object, FStringView Field, int32 Min, int32 Max, int32& Out)
    {
        const TSharedPtr<FJsonValue> Value = Object.TryGetField(Field);
        double Number = 0;
        if (!Value.IsValid() || Value->Type != EJson::Number || !Value->TryGetNumber(Number) ||
            !(Number >= Min && Number <= Max))
        {
            return false;
        }
        Out = static_cast<int32>(Number);
        return Number == Out;
    }

    using FConfigRows = TArray<TSharedPtr<FJsonValue>>;

    bool ReadTable(const FString& Directory, const FString& Name, const FJsonValue& Record, FConfigRows& Rows)
    {
        if (!Name.EndsWith(TEXT(".json"), ESearchCase::CaseSensitive) ||
            !IsTableIdentifier(FStringView(Name).LeftChop(5)) || Name.Equals(TEXT("manifest.json"), ESearchCase::IgnoreCase) ||
            Record.Type != EJson::Object)
        {
            return false;
        }
        const TSharedPtr<FJsonObject>& Entry = Record.AsObject();
        FString Hash;
        int32 Size = 0;
        int32 RowCount = 0;
        TArray<uint8> Bytes;
        return Entry.IsValid() && Entry->Values.Num() == 3 && ReadString(*Entry, TEXT("sha256"), Hash) && IsLowerSha256(Hash) &&
            ReadInt(*Entry, TEXT("size"), 1, MaxTableBytes, Size) && ReadInt(*Entry, TEXT("rows"), 1, MaxRows, RowCount) &&
            ReadConfigBytes(Directory / Name, Size, Bytes) && Bytes.Num() == Size && MatchesSha256(Bytes, Hash) &&
            FJsonSerializer::Deserialize(MakeJsonReader(Bytes), Rows) && Rows.Num() == RowCount;
    }

    bool InspectTables(const FString& Directory, const FJsonObject& Files, FProfileDedicatedConfigSummary& Summary, FString& Error)
    {
        struct FEnemy
        {
            FString Name;
            int32 AiBudget;
        };
        struct FWave
        {
            FString EnemyId;
            int32 Count;
        };

        TMap<FString, FEnemy> Enemies;
        TArray<FWave> Waves;
        for (const auto& File : Files.Values)
        {
            const FString FileName(File.Key);
            FConfigRows Rows;
            if (!File.Value.IsValid() || !ReadTable(Directory, FileName, *File.Value, Rows))
            {
                Error = TEXT("A listed JSON table is missing or differs from the pinned manifest");
                return false;
            }

            TSet<FString> Names;
            for (const TSharedPtr<FJsonValue>& Value : Rows)
            {
                const TSharedPtr<FJsonObject> Row = Value.IsValid() && Value->Type == EJson::Object ? Value->AsObject() : nullptr;
                FString Name;
                if (!Row.IsValid() || !ReadString(*Row, TEXT("Name"), Name) || !IsTableIdentifier(Name) || Names.Contains(Name))
                {
                    Error = TEXT("A listed table contains an invalid or duplicate row name");
                    return false;
                }
                Names.Add(Name);
                if (FileName.Equals(TEXT("Enemies.json"), ESearchCase::CaseSensitive))
                {
                    int32 AiBudget = 0;
                    if (!ReadInt(*Row, TEXT("AiBudget"), 0, MAX_int32, AiBudget))
                    {
                        Error = TEXT("Enemies.json requires an integer AiBudget for each enemy");
                        return false;
                    }
                    Enemies.Add(Name, FEnemy{Name, AiBudget});
                }
                else if (FileName.Equals(TEXT("Waves.json"), ESearchCase::CaseSensitive))
                {
                    FWave Wave;
                    if (!ReadString(*Row, TEXT("EnemyId"), Wave.EnemyId) || !ReadInt(*Row, TEXT("Count"), 1, MAX_int32, Wave.Count))
                    {
                        Error = TEXT("Waves.json requires an EnemyId and positive integer Count for each wave");
                        return false;
                    }
                    Waves.Add(MoveTemp(Wave));
                }
            }
        }

        if (Enemies.IsEmpty() || Waves.IsEmpty())
        {
            Error = TEXT("The pinned manifest must include nonempty Enemies.json and Waves.json tables");
            return false;
        }
        int64 WaveAiBudget = 0;
        for (const FWave& Wave : Waves)
        {
            const FEnemy* Enemy = Enemies.Find(Wave.EnemyId);
            if (!Enemy || !Enemy->Name.Equals(Wave.EnemyId, ESearchCase::CaseSensitive))
            {
                Error = TEXT("Waves.json references an unknown EnemyId");
                return false;
            }
            const int64 Contribution = static_cast<int64>(Enemy->AiBudget) * Wave.Count;
            if (Contribution > MAX_int64 - WaveAiBudget)
            {
                Error = TEXT("Total wave AI budget exceeds the supported range");
                return false;
            }
            WaveAiBudget += Contribution;
        }
        Summary = {Enemies.Num(), Waves.Num(), WaveAiBudget};
        return true;
    }
}

bool LoadProfileDedicatedConfig(const FString& SharedConfigId, FProfileDedicatedConfigSummary& Summary, FString& Error)
{
    FString Directory;
    FString ManifestHash;
    if (!FParse::Value(FCommandLine::Get(), TEXT("-AdoptionServerConfigDir="), Directory, false) ||
        !FParse::Value(FCommandLine::Get(), TEXT("-AdoptionServerManifestSha256="), ManifestHash) || !IsLowerSha256(ManifestHash))
    {
        Error = TEXT("Both -AdoptionServerConfigDir and a lowercase -AdoptionServerManifestSha256 are required");
        return false;
    }
    FPaths::NormalizeFilename(Directory);
    if (Directory.Len() < 3 || !IsAsciiLetter(Directory[0]) || Directory[1] != ':' || Directory[2] != '/')
    {
        Error = TEXT("-AdoptionServerConfigDir must be a local absolute Windows path");
        return false;
    }

    TArray<uint8> ManifestBytes;
    if (!ReadConfigBytes(Directory / TEXT("manifest.json"), MaxManifestBytes, ManifestBytes) ||
        !MatchesSha256(ManifestBytes, ManifestHash))
    {
        Error = TEXT("Server manifest is missing or does not match its pinned SHA-256");
        return false;
    }

    TSharedPtr<FJsonObject> Manifest;
    FString Compatibility;
    FString SourceHash;
    int32 SchemaVersion = 0;
    const TSharedPtr<FJsonObject>* Files = nullptr;
    if (!FJsonSerializer::Deserialize(MakeJsonReader(ManifestBytes), Manifest) || !Manifest.IsValid() || Manifest->Values.Num() != 4 ||
        !ReadInt(*Manifest, TEXT("schemaVersion"), 1, 1, SchemaVersion) ||
        !ReadString(*Manifest, TEXT("compatibilitySha256"), Compatibility) || !Compatibility.Equals(SharedConfigId, ESearchCase::CaseSensitive) ||
        !ReadString(*Manifest, TEXT("sourceSha256"), SourceHash) || !IsLowerSha256(SourceHash) ||
        !Manifest->TryGetObjectField(TEXT("files"), Files) || !Files->IsValid() ||
        (*Files)->Values.IsEmpty() || (*Files)->Values.Num() > MaxFiles)
    {
        Error = TEXT("Server manifest has an unsupported schema or does not match the cooked shared configuration");
        return false;
    }
    return InspectTables(Directory, **Files, Summary, Error);
}
