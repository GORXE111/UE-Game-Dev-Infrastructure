package com.example.samplegame.update;

import android.content.Context;
import android.util.AtomicFile;
import dalvik.system.BaseDexClassLoader;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** Host Android API doubles verify transactions and selection logic, not real Android compatibility. */
public final class NativeUpdateLoaderTest {
    private static int checks;
    private static KeyPair keys;
    private static JSONObject profile;
    private static File root;
    private static byte[] goodElf;
    private static final Map<String, byte[]> responses = new HashMap<>();
    private static int httpStatus = 200;

    interface Action { void run() throws Exception; }

    private static void check(boolean condition, String label) {
        ++checks;
        if (!condition) throw new AssertionError(label);
    }

    private static void rejects(Action action, String label) throws Exception {
        boolean rejected = false;
        try { action.run(); }
        catch (Exception error) { rejected = true; }
        check(rejected, label);
    }

    private static void set(String name, Object value) throws Exception {
        Field field = NativeUpdate.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }

    private static Object get(String name) throws Exception {
        Field field = NativeUpdate.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private static Object invoke(String name, Class<?>[] types, Object... arguments) throws Exception {
        Method method = NativeUpdate.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        try { return method.invoke(null, arguments); }
        catch (InvocationTargetException error) {
            if (error.getCause() instanceof Exception) throw (Exception) error.getCause();
            throw error;
        }
    }

    private static JSONObject payload(long release) throws Exception {
        JSONObject value = new JSONObject(profile.toString());
        value.remove("enabled");
        value.remove("manifestUrl");
        value.put("platform", "Android_ARM64");
        value.put("releaseId", release);
        value.put("nativeSourceHash", "b".repeat(64));
        value.put("soSha256", NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(goodElf)));
        value.put("soSize", goodElf.length);
        value.put("soUrl", "https://updates.example.com/r" + release + ".so");
        value.put("versionLabel", "1.0.4.1");
        return value;
    }

    private static byte[] envelope(JSONObject value) throws Exception {
        byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keys.getPrivate());
        signer.update(bytes);
        return new JSONObject().put("format", 1).put("signatureAlgorithm", "SHA256withRSA")
                .put("payloadBase64", Base64.getEncoder().encodeToString(bytes))
                .put("signatureBase64", Base64.getEncoder().encodeToString(signer.sign()))
                .toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void verify(byte[] bytes) throws Exception {
        invoke("verifyEnvelope", new Class<?>[] { byte[].class }, bytes);
    }

    private static File library(JSONObject value) throws Exception {
        return (File) invoke("libraryFile", new Class<?>[] { JSONObject.class }, value);
    }

    private static void stage(JSONObject value) throws Exception {
        responses.put(profile.getString("manifestUrl"), envelope(value));
        responses.put(value.getString("soUrl"), goodElf);
        invoke("checkAndStage", new Class<?>[0]);
    }

    private static void resetSelection() throws Exception {
        set("libraryLoaded", false);
        set("candidateLoaded", false);
        set("selectedRelease", 0L);
        set("selectedAttempt", "");
        set("readyRelease", 0L);
        set("selectedPath", "apk:lib/arm64-v8a/libUnreal.so");
        set("selectedHash", profile.getString("baseNativeSourceHash"));
        set("state", "Base");
    }

    private static void pending(long release) throws Exception {
        String attempt = (String) get("selectedAttempt");
        if (attempt.isEmpty()) {
            attempt = UUID.randomUUID().toString();
            set("selectedAttempt", attempt);
        }
        JSONObject marker = new JSONObject().put("releaseId", release).put("attemptId", attempt);
        invoke("writeBootMarker", new Class<?>[] { String.class, JSONObject.class }, "boot-pending", marker);
    }

    private static Object install(BaseDexClassLoader loader, File library) throws Exception {
        Class<?> type = Class.forName("com.example.samplegame.update.NativeUpdate$PathChange");
        Method method = type.getDeclaredMethod("install", ClassLoader.class, File.class);
        method.setAccessible(true);
        try { return method.invoke(null, loader, library); }
        catch (InvocationTargetException error) { throw (Exception) error.getCause(); }
    }

    private static void restore(Object change) throws Exception {
        Method method = change.getClass().getDeclaredMethod("restore");
        method.setAccessible(true);
        method.invoke(change);
    }

    private static void expectNativeFailure(Context context, BaseDexClassLoader loader) {
        try {
            NativeUpdate.loadUnreal(context, loader);
            throw new AssertionError("Host must never successfully load the fake ARM64 ELF");
        } catch (UnsatisfiedLinkError expected) { /* The host is intentionally not an Android runtime. */ }
    }

    public static void main(String[] args) throws Exception {
        URL.setURLStreamHandlerFactory(protocol -> protocol.equals("https") ? new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL url) {
                return new HttpURLConnection(url) {
                    @Override public int getResponseCode() { return httpStatus; }
                    @Override public long getContentLengthLong() { return responses.get(url.toString()).length; }
                    @Override public InputStream getInputStream() { return new ByteArrayInputStream(responses.get(url.toString())); }
                    @Override public void disconnect() {}
                    @Override public boolean usingProxy() { return false; }
                    @Override public void connect() {}
                };
            }
        } : null);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        root = Files.createTempDirectory("native-loader-test-").toFile();
        ByteBuffer elf = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN);
        elf.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, 1, 1 }).position(16);
        elf.putShort((short) 3).putShort((short) 183).putInt(1).putLong(0).putLong(64).putLong(0).putInt(0);
        elf.putShort((short) 64).putShort((short) 56).putShort((short) 1);
        elf.position(64);
        elf.putInt(1).putInt(5).putLong(0).putLong(0).putLong(0).putLong(256).putLong(256).putLong(16384);
        goodElf = elf.array();
        profile = new JSONObject().put("format", 1).put("enabled", true).put("packageName", "com.example.samplegame")
                .put("channel", "native-test").put("baseReleaseId", 300).put("baseNativeSourceHash", "a".repeat(64))
                .put("nativeApiVersion", 2).put("engineBuildId", "test-engine").put("abi", "arm64-v8a")
                .put("manifestUrl", "https://updates.example.com/manifest.json").put("contentCompatibilityId", "content-base-test");
        Context context = new Context();
        set("context", context);
        set("bootstrap", profile);
        set("root", root);
        set("publicKey", keys.getPublic());
        try {
            JSONObject valid = payload(301);
            verify(envelope(valid));
            check(true, "Full signed native envelope accepted");
            String[] bindingFields = { "packageName", "channel", "baseNativeSourceHash", "engineBuildId", "abi", "contentCompatibilityId", "platform" };
            for (String field : bindingFields) {
                JSONObject bad = new JSONObject(valid.toString()).put(field, "incorrect");
                rejects(() -> verify(envelope(bad)), "Binding rejected: " + field);
            }
            for (String field : new String[] { "baseReleaseId", "nativeApiVersion" }) {
                JSONObject bad = new JSONObject(valid.toString()).put(field, 3);
                rejects(() -> verify(envelope(bad)), "Numeric binding rejected: " + field);
            }
            rejects(() -> verify(envelope(new JSONObject(valid.toString()).put("releaseId", 300))), "Base release cannot be patch");
            rejects(() -> verify(envelope(new JSONObject(valid.toString()).put("soSize", "256"))), "Numeric string rejected");
            rejects(() -> verify(envelope(new JSONObject(valid.toString()).put("releaseId", 301.5))), "Fractional release rejected");
            rejects(() -> verify(envelope(new JSONObject(valid.toString()).put("soUrl", "http://updates.example.com/r.so"))), "HTTP manifest payload rejected");
            rejects(() -> verify(envelope(new JSONObject(valid.toString()).put("soUrl", "https://attacker.example/r.so"))), "Foreign payload origin rejected");
            rejects(() -> verify(new byte[] { (byte) 0xff }), "Invalid UTF8 rejected");
            rejects(() -> verify(new byte[65537]), "Oversized envelope rejected");
            JSONObject changedEnvelope = new JSONObject(new String(envelope(valid), StandardCharsets.UTF_8));
            changedEnvelope.put("signatureBase64", Base64.getEncoder().encodeToString(new byte[256]));
            rejects(() -> verify(changedEnvelope.toString().getBytes(StandardCharsets.UTF_8)), "Envelope signature rejected");

            File original = new File(root, "original");
            check(original.mkdir(), "Original directory created");
            File originalLibrary = new File(original, "libUnreal.so");
            Files.write(originalLibrary.toPath(), goodElf);
            File candidateLibrary = library(valid);
            Files.write(candidateLibrary.toPath(), goodElf);
            BaseDexClassLoader loader = new BaseDexClassLoader(original);
            Object change = install(loader, candidateLibrary);
            check(new File(loader.findLibrary("Unreal")).getCanonicalFile().equals(candidateLibrary.getCanonicalFile()), "Java and NativeActivity select same candidate");
            restore(change);
            check(new File(loader.findLibrary("Unreal")).equals(originalLibrary), "Original search path restored");
            BaseDexClassLoader.failMake = true;
            rejects(() -> install(loader, candidateLibrary), "Unsupported path-element creation rejected");
            BaseDexClassLoader.failMake = false;
            check(new File(loader.findLibrary("Unreal")).equals(originalLibrary), "Failed injection preserves original path");
            BaseDexClassLoader.denyReflection = true;
            rejects(() -> install(loader, candidateLibrary), "Platform reflection denial rejected");
            BaseDexClassLoader.denyReflection = false;
            check(new File(loader.findLibrary("Unreal")).equals(originalLibrary), "Denied reflection restores original path");
            rejects(() -> install(new BaseDexClassLoader(original) { }, new File(candidateLibrary.getParentFile(), "missing.so")),
                    "Unexpected selected filename rejected");
            BaseDexClassLoader.ignoreFirst = true;
            rejects(() -> install(loader, candidateLibrary), "ClassLoader path mismatch rejected");
            BaseDexClassLoader.ignoreFirst = false;
            check(new File(loader.findLibrary("Unreal")).equals(originalLibrary), "Mismatch rollback restores original path");

            stage(valid);
            check(new File(root, "active.json").isFile(), "Signed active transaction written");
            check(get("state").equals("ReadyToRestart"), "Prepared candidate requires cold restart");
            check(new String(Files.readAllBytes(new File(root, "high-water").toPath()), StandardCharsets.UTF_8).equals("301"), "Anti-rollback high-water persisted");
            check(!candidateLibrary.canWrite(), "Existing verified destination protected before activation");
            rejects(() -> stage(payload(300)), "Old/base manifest rejected before download");
            JSONObject second = payload(302);
            responses.put(profile.getString("manifestUrl"), envelope(second));
            responses.put(second.getString("soUrl"), new byte[255]);
            rejects(() -> invoke("checkAndStage", new Class<?>[0]), "Truncated native HTTP payload rejected");
            check(!new File(library(second).getParentFile(), "libUnreal.so.part").exists(), "Partial download cleaned");
            check(new JSONObject(new String(Files.readAllBytes(new File(root, "active.json").toPath()), StandardCharsets.UTF_8)).has("signatureBase64"), "Previous active envelope preserved after failed download");
            httpStatus = 302;
            rejects(() -> invoke("checkAndStage", new Class<?>[0]), "HTTP redirect rejected");
            httpStatus = 200;
            responses.put(second.getString("soUrl"), goodElf);
            AtomicFile.failFinishName = "active.json";
            rejects(() -> invoke("checkAndStage", new Class<?>[0]), "Injected activation commit failure");
            verify(Files.readAllBytes(new File(root, "active.json").toPath()));
            check(new String(Files.readAllBytes(new File(root, "high-water").toPath()), StandardCharsets.UTF_8).equals("301"), "Failed activation preserves high-water");
            check(candidateLibrary.setWritable(true, true), "Interrupted writable candidate simulated");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(!candidateLibrary.canWrite(), "Candidate permissions repaired again before native execution");
            check(get("state").equals("NativeLoadFailed"), "Native loader failure recorded without same-process base attempt");
            check(new File(root, "boot-pending").isFile(), "Failure keeps startup marker for next process");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(get("state").equals("RolledBack"), "Next clean launch chooses APK after unconfirmed startup");
            check(!new File(root, "boot-pending").exists(), "Pending startup cleared during recovery");
            check(new String(Files.readAllBytes(new File(root, "blocked-release").toPath()), StandardCharsets.UTF_8).equals("301"), "Failed release blocked from repeated activation");
            check(((Long) get("selectedRelease")) == 0L, "Recovery selects no native patch");
            stage(second);
            check(get("state").equals("ReadyToRestart"), "Higher signed release can recover after block");
            set("candidateLoaded", true);
            set("selectedRelease", 302L);
            pending(302L);
            NativeUpdate.confirmStableStartup();
            check(!new File(root, "boot-pending").exists(), "Stable startup confirmation clears marker");
            check(new String(Files.readAllBytes(new File(root, "confirmed-release").toPath()), StandardCharsets.UTF_8).equals("302"), "Confirmed release persisted");
            JSONObject status = new JSONObject(NativeUpdate.statusJson());
            check(!status.getBoolean("startupPending"), "Public status reports confirmation");

            pending(302L);
            AtomicFile.silentFailDeleteName = "boot-pending";
            NativeUpdate.confirmStableStartup();
            check(get("state").equals("ConfirmationFailed"), "Silent pending-delete failure reported");
            check(new JSONObject(NativeUpdate.statusJson()).getBoolean("startupPending"), "Failed confirmation remains pending for C++ retry");
            NativeUpdate.confirmStableStartup();
            check(!new JSONObject(NativeUpdate.statusJson()).getBoolean("startupPending"), "Confirmation retry succeeds without restarting");

            pending(302L);
            check(new File(root, "boot-pending").renameTo(new File(root, "boot-pending.bak")), "Interrupted marker backup prepared");
            check(new JSONObject(NativeUpdate.statusJson()).getBoolean("startupPending"), "Marker backup is still pending");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(get("state").equals("NativeLoadFailed"), "Confirmed marker recovery continues candidate instead of false rollback");
            check(new String(Files.readAllBytes(new File(root, "blocked-release").toPath()), StandardCharsets.UTF_8).equals("301"),
                    "Confirmed release not falsely blocked");
            invoke("deleteMetadata", new Class<?>[] { String.class }, "boot-pending");

            AtomicFile.silentFailFinishName = "boot-pending";
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(get("state").equals("BaseFallback"), "Silent boot-marker commit failure prevents candidate System.load");
            check(!((Boolean) get("candidateLoaded")), "Candidate not loaded without durable marker readback");
            check(((Long) get("selectedRelease")) == 0L, "Marker failure keeps base selection");

            JSONObject third = payload(303);
            AtomicFile.silentFailFinishName = "active.json";
            rejects(() -> stage(third), "Silent activation commit failure detected by readback");
            JSONObject stillSecond = (JSONObject) invoke("verifyEnvelope", new Class<?>[] { byte[].class },
                    Files.readAllBytes(new File(root, "active.json").toPath()));
            check(stillSecond.getLong("releaseId") == 302, "Silent activation failure preserves previous candidate");

            JSONObject fifth = payload(305);
            AtomicFile.failFinishName = "high-water";
            rejects(() -> stage(fifth), "High-water failure after activation injected");
            JSONObject activeFifth = (JSONObject) invoke("verifyEnvelope", new Class<?>[] { byte[].class },
                    Files.readAllBytes(new File(root, "active.json").toPath()));
            check(activeFifth.getLong("releaseId") == 305, "New active survives independent water failure");
            check(new String(Files.readAllBytes(new File(root, "high-water").toPath()), StandardCharsets.UTF_8).equals("302"),
                    "Water intentionally lags after failed second commit");
            stage(payload(304));
            check(get("state").equals("UpToDate"), "Signed intermediate downgrade rejected against verified active");
            activeFifth = (JSONObject) invoke("verifyEnvelope", new Class<?>[] { byte[].class },
                    Files.readAllBytes(new File(root, "active.json").toPath()));
            check(activeFifth.getLong("releaseId") == 305, "Lower release cannot replace higher active candidate");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(new String(Files.readAllBytes(new File(root, "high-water").toPath()), StandardCharsets.UTF_8).equals("305"),
                    "Next candidate load repairs lagging high-water before execution");
            NativeUpdate.confirmStableStartup();
            check(!new JSONObject(NativeUpdate.statusJson()).getBoolean("startupPending"), "Fifth release confirmation recorded for this attempt");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(get("state").equals("NativeLoadFailed"), "Previously confirmed release still receives a new startup attempt");
            resetSelection();
            expectNativeFailure(context, new BaseDexClassLoader(original));
            check(get("state").equals("RolledBack"), "New failed attempt is not exempted by an older confirmation of same release");
            check(new String(Files.readAllBytes(new File(root, "blocked-release").toPath()), StandardCharsets.UTF_8).equals("305"),
                    "Repeated startup failure blocks even a previously confirmed release");
        } finally {
            try (var paths = Files.walk(root.toPath())) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { path.toFile().setWritable(true); Files.deleteIfExists(path); }
                    catch (Exception error) { throw new RuntimeException(error); }
                });
            }
        }
        check(checks >= 45, "Complete lifecycle coverage executed");
        System.out.println("NativeUpdateLoaderTest: " + checks + " checks passed (host doubles; not an Android device test)");
    }
}
