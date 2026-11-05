#include "SampleGameNativeUpdateSubsystem.h"

#include "Dom/JsonObject.h"
#include "Engine/GameInstance.h"
#include "Engine/World.h"
#include "HAL/PlatformTime.h"
#include "Modules/ModuleManager.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"

#if PLATFORM_ANDROID
#include "Android/AndroidJavaEnv.h"
#endif

DEFINE_LOG_CATEGORY_STATIC(LogSampleGameNativeUpdate, Log, All);
IMPLEMENT_MODULE(FDefaultModuleImpl, SampleGameNativeUpdate)

namespace
{
#if PLATFORM_ANDROID
bool CallNativeUpdateJava(const ANSICHAR* MethodName, FString* Result = nullptr)
{
    JNIEnv* Env = AndroidJavaEnv::GetJavaEnv();
    if (!Env) return false;
    jclass Class = AndroidJavaEnv::FindJavaClass("com/example/samplegame/update/ReleasePlayer");
    if (Env->ExceptionCheck())
    {
        Env->ExceptionClear();
        UE_LOG(LogSampleGameNativeUpdate, Warning, TEXT("Native update Java class lookup failed"));
        return false;
    }
    if (!Class) return false;
    jmethodID Method = Env->GetStaticMethodID(Class, MethodName, Result ? "()Ljava/lang/String;" : "()V");
    bool bSuccess = Method != nullptr && !Env->ExceptionCheck();
    if (bSuccess)
    {
        if (Result)
        {
            jstring Text = static_cast<jstring>(Env->CallStaticObjectMethod(Class, Method));
            bSuccess = Text != nullptr && !Env->ExceptionCheck();
            if (bSuccess)
            {
                const char* Utf8 = Env->GetStringUTFChars(Text, nullptr);
                if (Utf8)
                {
                    *Result = UTF8_TO_TCHAR(Utf8);
                    Env->ReleaseStringUTFChars(Text, Utf8);
                }
                else bSuccess = false;
            }
            if (Text) Env->DeleteLocalRef(Text);
        }
        else Env->CallStaticVoidMethod(Class, Method);
    }
    if (Env->ExceptionCheck())
    {
        Env->ExceptionClear();
        bSuccess = false;
    }
    Env->DeleteLocalRef(Class);
    if (!bSuccess) UE_LOG(LogSampleGameNativeUpdate, Warning, TEXT("Native update Java call failed: %hs"), MethodName);
    return bSuccess;
}
#endif
}

void USampleGameNativeUpdateSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    UE_LOG(LogSampleGameNativeUpdate, Display, TEXT("SAMPLEGAME_NATIVE_BUILD revision=9"));
#if PLATFORM_ANDROID
    RefreshStatus();
    TickerHandle = FTSTicker::GetCoreTicker().AddTicker(
        FTickerDelegate::CreateUObject(this, &ThisClass::TickStatus), 1.0f);
#endif
}

void USampleGameNativeUpdateSubsystem::Deinitialize()
{
    if (TickerHandle.IsValid())
    {
        FTSTicker::GetCoreTicker().RemoveTicker(TickerHandle);
        TickerHandle.Reset();
    }
    Super::Deinitialize();
}

void USampleGameNativeUpdateSubsystem::CheckForNativeUpdate()
{
#if PLATFORM_ANDROID
    CallNativeUpdateJava("checkForUpdates");
    RefreshStatus();
#endif
}

void USampleGameNativeUpdateSubsystem::RefreshStatus()
{
#if PLATFORM_ANDROID
    FString Next;
    if (!CallNativeUpdateJava("statusJson", &Next) || Next.Len() > 65536) return;
    if (Next == StatusJson) return;
    TSharedPtr<FJsonObject> Object;
    if (!FJsonSerializer::Deserialize(TJsonReaderFactory<>::Create(Next), Object) || !Object.IsValid()) return;
    bool bNextRestart = false;
    bool bNextPending = false;
    FString NextState;
    if (!Object->TryGetBoolField(TEXT("restartRequired"), bNextRestart)
        || !Object->TryGetBoolField(TEXT("startupPending"), bNextPending)
        || !Object->TryGetStringField(TEXT("state"), NextState)) return;
    bRestartRequired = bNextRestart;
    bStartupPending = bNextPending;
    bStartupStatusKnown = true;
    if (NextState != LastState)
    {
        UE_LOG(LogSampleGameNativeUpdate, Display, TEXT("Native update: %s"), *Next);
        LastState = NextState;
    }
    if (StatusJson != Next)
    {
        StatusJson = MoveTemp(Next);
        OnStatusChanged.Broadcast(StatusJson);
    }
#endif
}

bool USampleGameNativeUpdateSubsystem::TickStatus(float DeltaSeconds)
{
#if PLATFORM_ANDROID
    UWorld* World = GetGameInstance() ? GetGameInstance()->GetWorld() : nullptr;
    if (!World || !World->IsGameWorld() || !World->HasBegunPlay())
    {
        StableWorld.Reset();
        StableWorldSince = 0.0;
        RefreshStatus();
        return true;
    }
    const double Now = FPlatformTime::Seconds();
    if (StableWorld.Get() != World)
    {
        StableWorld = World;
        StableWorldSince = Now;
    }
    const double StableSeconds = Now - StableWorldSince;
    if (!bAutomaticCheckStarted && StableSeconds >= 3.0)
    {
        bAutomaticCheckStarted = true;
        CheckForNativeUpdate();
    }
    // Only SampleGameReleaseSession can acknowledge the selected native/PAK/Lua/
    // save identity. A stable world by itself is insufficient evidence.
    RefreshStatus();
#endif
    return true;
}
