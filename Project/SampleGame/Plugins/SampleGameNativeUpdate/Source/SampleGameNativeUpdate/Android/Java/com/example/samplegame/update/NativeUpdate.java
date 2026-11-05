package com.example.samplegame.update;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.AtomicFile;
import android.util.Base64;
import android.util.Log;

import dalvik.system.BaseDexClassLoader;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/** The only Android libUnreal selection point. No native library is needed to verify a candidate. */
public final class NativeUpdate {
    private static final String TAG = "SampleGameNativeUpdate";
    private static final int MAX_MANIFEST = 65536;
    private static Context context;
    private static JSONObject bootstrap;
    private static File root;
    private static PublicKey publicKey;
    private static boolean libraryLoaded;
    private static boolean checking;
    private static boolean candidateLoaded;
    private static long selectedRelease;
    private static String selectedAttempt = "";
    private static String state = "NotInitialized";
    private static String message = "";
    private static String selectedPath = "apk:lib/arm64-v8a/libUnreal.so";
    private static String selectedHash = "";
    private static long receivedBytes;
    private static long totalBytes;
    private static long readyRelease;

    private NativeUpdate() {}

    private static String text(JSONObject value, String key) throws Exception {
        return boundedText(value, key, 4096);
    }

    private static String boundedText(JSONObject value, String key, int maximum) throws Exception {
        Object raw = value.get(key);
        NativeUpdatePolicy.require(raw instanceof String && !((String) raw).isEmpty()
                && ((String) raw).length() <= maximum, "Invalid string field: " + key);
        return (String) raw;
    }

    private static long number(JSONObject value, String key) throws Exception {
        Object raw = value.get(key);
        NativeUpdatePolicy.require(raw instanceof Number, "Invalid numeric field: " + key);
        double floating = ((Number) raw).doubleValue();
        long result = ((Number) raw).longValue();
        NativeUpdatePolicy.require(result >= 0 && result <= 9007199254740991L && floating == result,
                "Out-of-range integer: " + key);
        return result;
    }

    private static String utf8(byte[] bytes) throws Exception {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static byte[] read(InputStream input, int maximum) throws Exception {
        try (InputStream source = input; ByteArrayOutputStream result = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = source.read(buffer)) != -1) {
                NativeUpdatePolicy.require(result.size() <= maximum - count, "Native metadata exceeds size limit");
                result.write(buffer, 0, count);
            }
            return result.toByteArray();
        }
    }

    private static boolean metadataExists(String name) throws Exception {
        return named(name).isFile() || named(name + ".bak").isFile();
    }

    private static byte[] readMetadata(String name, int maximum) throws Exception {
        return read(new AtomicFile(named(name)).openRead(), maximum);
    }

    private static void atomicWrite(File destination, byte[] bytes) throws Exception {
        NativeUpdatePolicy.require(destination.getCanonicalFile().getParentFile().equals(root.getCanonicalFile()),
                "Native metadata outside private root");
        AtomicFile file = new AtomicFile(destination);
        FileOutputStream output = null;
        try {
            output = file.startWrite();
            output.write(bytes);
            output.getFD().sync();
            file.finishWrite(output);
        } catch (Exception error) {
            if (output != null) file.failWrite(output);
            throw error;
        }
        // Android AtomicFile may log a failed final rename without throwing.
        NativeUpdatePolicy.require(Arrays.equals(bytes, readMetadata(destination.getName(), MAX_MANIFEST)),
                "Native metadata commit did not survive readback");
    }

    private static void initialize(Context appContext) throws Exception {
        if (context != null) return;
        context = appContext.getApplicationContext();
        bootstrap = new JSONObject(utf8(read(context.getAssets().open("native-bootstrap.json"), MAX_MANIFEST)));
        NativeUpdatePolicy.require(number(bootstrap, "format") == 1, "Unsupported native bootstrap format");
        NativeUpdatePolicy.require(text(bootstrap, "packageName").equals(context.getPackageName()), "Bootstrap package mismatch");
        NativeUpdatePolicy.require(text(bootstrap, "abi").equals("arm64-v8a"), "Native bootstrap ABI mismatch");
        NativeUpdatePolicy.requireSha256(text(bootstrap, "baseNativeSourceHash"));
        NativeUpdatePolicy.require(number(bootstrap, "baseReleaseId") > 0, "Missing native base release");
        NativeUpdatePolicy.require(number(bootstrap, "nativeApiVersion") > 0, "Missing native API version");
        text(bootstrap, "engineBuildId");
        text(bootstrap, "channel");
        text(bootstrap, "contentCompatibilityId");
        NativeUpdatePolicy.requireHttps(text(bootstrap, "manifestUrl"));
        selectedHash = text(bootstrap, "baseNativeSourceHash");
        File privateDirectory = context.getDir("samplegame-native-updates", Context.MODE_PRIVATE);
        root = NativeUpdatePolicy.child(privateDirectory, "b" + number(bootstrap, "baseReleaseId") + "-"
                + text(bootstrap, "baseNativeSourceHash").substring(0, 16));
        NativeUpdatePolicy.require(root.isDirectory() || root.mkdir(), "Cannot create native update directory");
        NativeUpdatePolicy.require(root.getCanonicalFile().getParentFile().equals(privateDirectory.getCanonicalFile()),
                "Native root is outside app-private storage");
        publicKey = trustedCertificateKey();
    }

    private static PublicKey trustedCertificateKey() throws Exception {
        // New bases pin release trust independently of an installer's APK
        // certificate, so cloud-device re-signing does not replace update trust.
        // Old base profiles retain their original installed-certificate policy.
        if (!bootstrap.has("nativeTrust")) return certificateKey();
        JSONObject trust = bootstrap.getJSONObject("nativeTrust");
        NativeUpdatePolicy.require(number(trust, "format") == 1, "Unsupported native trust format");
        String expected = boundedText(trust, "certificateSha256", 64);
        NativeUpdatePolicy.requireSha256(expected);
        byte[] certificate = Base64.decode(boundedText(trust, "certificateBase64", 8192), Base64.NO_WRAP);
        NativeUpdatePolicy.require(certificate.length > 0 && certificate.length <= 4096, "Invalid native trust certificate size");
        String actual = NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(certificate));
        NativeUpdatePolicy.require(actual.equals(expected), "Native trust certificate hash mismatch");
        return CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(certificate)).getPublicKey();
    }

    @SuppressWarnings("deprecation")
    private static PublicKey certificateKey() throws Exception {
        android.content.pm.Signature[] signatures;
        PackageManager manager = context.getPackageManager();
        if (Build.VERSION.SDK_INT >= 28) {
            PackageInfo info = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            NativeUpdatePolicy.require(info.signingInfo != null, "Installed APK signing information absent");
            signatures = info.signingInfo.getApkContentsSigners();
        } else {
            signatures = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures;
        }
        NativeUpdatePolicy.require(signatures != null && signatures.length == 1, "Expected one installed APK signer");
        return CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(signatures[0].toByteArray())).getPublicKey();
    }

    private static boolean enabled() {
        return bootstrap != null && bootstrap.optBoolean("enabled", false);
    }

    private static File named(String name) throws Exception {
        return NativeUpdatePolicy.child(root, name);
    }

    private static JSONObject verifyEnvelope(byte[] envelopeBytes) throws Exception {
        NativeUpdatePolicy.require(envelopeBytes.length > 0 && envelopeBytes.length <= MAX_MANIFEST, "Invalid manifest size");
        JSONObject envelope = new JSONObject(utf8(envelopeBytes));
        NativeUpdatePolicy.require(number(envelope, "format") == 1, "Unsupported native manifest envelope");
        byte[] payload = Base64.decode(boundedText(envelope, "payloadBase64", 45000), Base64.NO_WRAP);
        byte[] signature = Base64.decode(boundedText(envelope, "signatureBase64", 12000), Base64.NO_WRAP);
        NativeUpdatePolicy.verifySignature(payload, signature, text(envelope, "signatureAlgorithm"), publicKey);
        JSONObject value = new JSONObject(utf8(payload));
        NativeUpdatePolicy.require(number(value, "format") == 1, "Unsupported native payload format");
        NativeUpdatePolicy.require(text(value, "platform").equals("Android_ARM64"), "Native payload platform mismatch");
        String[] strings = { "packageName", "channel", "baseNativeSourceHash", "engineBuildId", "abi", "contentCompatibilityId" };
        for (String key : strings) NativeUpdatePolicy.require(text(value, key).equals(text(bootstrap, key)), "Native binding mismatch: " + key);
        String[] integers = { "baseReleaseId", "nativeApiVersion" };
        for (String key : integers) NativeUpdatePolicy.require(number(value, key) == number(bootstrap, key), "Native binding mismatch: " + key);
        NativeUpdatePolicy.require(number(value, "releaseId") > number(bootstrap, "baseReleaseId"), "Native release must follow base");
        NativeUpdatePolicy.requireSha256(text(value, "nativeSourceHash"));
        NativeUpdatePolicy.requireSha256(text(value, "soSha256"));
        long size = number(value, "soSize");
        NativeUpdatePolicy.require(size >= 64 && size <= NativeUpdatePolicy.MAX_SO_BYTES, "Native payload size out of bounds");
        NativeUpdatePolicy.requireSameOrigin(text(bootstrap, "manifestUrl"), text(value, "soUrl"));
        text(value, "versionLabel");
        return value;
    }

    private static File libraryFile(JSONObject value) throws Exception {
        File directory = named("r" + number(value, "releaseId") + "-" + text(value, "soSha256"));
        NativeUpdatePolicy.require(directory.isDirectory() || directory.mkdir(), "Cannot create private native version directory");
        NativeUpdatePolicy.require(directory.getCanonicalFile().equals(new File(root.getCanonicalFile(), directory.getName())),
                "Native version directory is aliased");
        File library = NativeUpdatePolicy.child(directory, "libUnreal.so");
        NativeUpdatePolicy.require(library.getCanonicalFile().equals(new File(directory.getCanonicalFile(), "libUnreal.so")),
                "Native library file is aliased");
        return library;
    }

    private static long storedNumber(String filename) throws Exception {
        if (!metadataExists(filename)) return 0;
        String value = utf8(readMetadata(filename, 64));
        NativeUpdatePolicy.require(value.matches("[0-9]{1,16}"), "Invalid persisted native version");
        return Long.parseLong(value);
    }

    private static void storeNumber(String filename, long value) throws Exception {
        atomicWrite(named(filename), Long.toString(value).getBytes(StandardCharsets.UTF_8));
    }

    private static JSONObject bootMarker(String name) throws Exception {
        if (!metadataExists(name)) return null;
        JSONObject value = new JSONObject(utf8(readMetadata(name, 1024)));
        NativeUpdatePolicy.require(number(value, "releaseId") > 0, "Invalid boot marker release");
        String attempt = text(value, "attemptId");
        NativeUpdatePolicy.require(UUID.fromString(attempt).toString().equals(attempt), "Invalid boot marker attempt");
        return value;
    }

    private static boolean sameAttempt(JSONObject first, JSONObject second) throws Exception {
        return first != null && second != null && number(first, "releaseId") == number(second, "releaseId")
                && text(first, "attemptId").equals(text(second, "attemptId"));
    }

    private static void writeBootMarker(String name, JSONObject value) throws Exception {
        atomicWrite(named(name), value.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void deleteMetadata(String filename) throws Exception {
        new AtomicFile(named(filename)).delete();
        NativeUpdatePolicy.require(!metadataExists(filename), "Could not clear native metadata: " + filename);
    }

    static void protectLibrary(File library) throws Exception {
        NativeUpdatePolicy.require(library.setReadable(true, true) && library.setWritable(false, false) && !library.canWrite(),
                "Could not protect verified native library permissions");
    }

    private static long verifiedActiveRelease() throws Exception {
        if (!metadataExists("active.json")) return 0;
        try { return number(verifyEnvelope(readMetadata("active.json", MAX_MANIFEST)), "releaseId"); }
        catch (Exception error) {
            Log.w(TAG, "Ignoring invalid active metadata while preserving independent anti-rollback records");
            return 0;
        }
    }

    private static void setState(String next, String detail) {
        state = next;
        message = detail == null ? "" : detail;
        Log.i(TAG, next + ": " + message);
    }

    /** Called by UE UPL before both System.load and NativeActivity.onCreate. */
    public static synchronized void loadUnreal(Context appContext, ClassLoader loader) {
        if (libraryLoaded) return;
        JSONObject candidate = null;
        File library = null;
        PathChange pathChange = null;
        try {
            initialize(appContext);
            if (!enabled()) {
                setState("Disabled", "Native updates disabled in this APK");
            } else {
                JSONObject pendingMarker = bootMarker("boot-pending");
                long pending = pendingMarker == null ? 0 : number(pendingMarker, "releaseId");
                if (pending > 0 && sameAttempt(pendingMarker, bootMarker("boot-confirmed"))) {
                    // Confirmation committed but process ended before marker removal.
                    deleteMetadata("boot-pending");
                    pending = 0;
                }
                if (pending > 0) {
                    storeNumber("blocked-release", Math.max(pending, storedNumber("blocked-release")));
                    deleteMetadata("boot-pending");
                    setState("RolledBack", "Previous native startup was not confirmed; using APK library");
                } else if (metadataExists("active.json")) {
                    candidate = verifyEnvelope(readMetadata("active.json", MAX_MANIFEST));
                    long release = number(candidate, "releaseId");
                    NativeUpdatePolicy.require(release > storedNumber("blocked-release"), "Candidate was disabled after startup failure");
                    library = libraryFile(candidate);
                    NativeUpdatePolicy.verifyFile(library, number(candidate, "soSize"), text(candidate, "soSha256"));
                    protectLibrary(library);
                    storeNumber("high-water", Math.max(release, storedNumber("high-water")));
                    selectedAttempt = UUID.randomUUID().toString();
                    writeBootMarker("boot-pending", new JSONObject().put("releaseId", release).put("attemptId", selectedAttempt));
                    pathChange = PathChange.install(loader, library);
                    selectedPath = library.getCanonicalPath();
                    selectedHash = text(candidate, "nativeSourceHash");
                    selectedRelease = release;
                    candidateLoaded = true;
                    setState("BootPending", "Verified native candidate selected for this process");
                } else {
                    setState("Base", "Using installed APK native library");
                }
            }
        } catch (Exception | LinkageError error) {
            if (pathChange != null) pathChange.restore();
            candidate = null;
            library = null;
            candidateLoaded = false;
            selectedRelease = 0;
            selectedAttempt = "";
            selectedPath = "apk:lib/arm64-v8a/libUnreal.so";
            selectedHash = bootstrap == null ? "" : bootstrap.optString("baseNativeSourceHash", "");
            try {
                if (root != null) {
                    JSONObject pendingMarker = bootMarker("boot-pending");
                    long pending = pendingMarker == null ? 0 : number(pendingMarker, "releaseId");
                    if (pending > 0 && !sameAttempt(pendingMarker, bootMarker("boot-confirmed")))
                        storeNumber("blocked-release", Math.max(pending, storedNumber("blocked-release")));
                    deleteMetadata("boot-pending");
                }
            } catch (Exception ignored) { Log.w(TAG, "Could not persist pre-load rejection"); }
            setState("BaseFallback", error.getClass().getSimpleName() + ": " + error.getMessage());
        }

        // A native failure may already have run global constructors. Do not load a second UE into this process.
        if (library != null && candidate != null) {
            try {
                System.load(selectedPath);
                libraryLoaded = true;
                Log.i(TAG, "Loaded native release " + selectedRelease + " source " + selectedHash);
            } catch (LinkageError error) {
                setState("NativeLoadFailed", error.toString());
                throw error;
            }
        } else {
            System.loadLibrary("Unreal");
            libraryLoaded = true;
        }
    }

    private static Field field(Class<?> type, String name) throws Exception {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                Field result = current.getDeclaredField(name);
                result.setAccessible(true);
                return result;
            } catch (NoSuchFieldException ignored) { /* Search the actual Android implementation hierarchy. */ }
        }
        throw new NoSuchFieldException(name);
    }

    /** Changes the existing application loader only; never creates another JNI namespace. */
    static final class PathChange {
        final Object pathList;
        final Field directoriesField;
        final Field elementsField;
        final Object oldDirectories;
        final Object oldElements;

        PathChange(Object list, Field directories, Field elements) throws Exception {
            pathList = list;
            directoriesField = directories;
            elementsField = elements;
            oldDirectories = directories.get(list);
            oldElements = elements.get(list);
        }

        static PathChange install(ClassLoader loader, File library) throws Exception {
            NativeUpdatePolicy.require(loader instanceof BaseDexClassLoader, "Unsupported application ClassLoader");
            Object list = field(BaseDexClassLoader.class, "pathList").get(loader);
            Field directories = field(list.getClass(), "nativeLibraryDirectories");
            Field elements = field(list.getClass(), "nativeLibraryPathElements");
            PathChange change = new PathChange(list, directories, elements);
            try {
                @SuppressWarnings("unchecked")
                List<File> original = (List<File>) change.oldDirectories;
                List<File> updated = new ArrayList<>();
                // The loader searches libUnreal.so by its conventional filename.
                File selectedDirectory = library.getParentFile();
                File conventional = NativeUpdatePolicy.child(selectedDirectory, "libUnreal.so");
                NativeUpdatePolicy.require(conventional.isFile() && conventional.getCanonicalFile().equals(library.getCanonicalFile()),
                        "Selected native library must use the conventional filename in its version directory");
                updated.add(selectedDirectory);
                updated.addAll(original);
                List<File> all = new ArrayList<>(updated);
                @SuppressWarnings("unchecked")
                List<File> system = (List<File>) field(list.getClass(), "systemNativeLibraryDirectories").get(list);
                all.addAll(system);
                Method make = list.getClass().getDeclaredMethod("makePathElements", List.class);
                make.setAccessible(true);
                Object nextElements = make.invoke(null, all);
                NativeUpdatePolicy.require(nextElements != null && nextElements.getClass().isArray() && Array.getLength(nextElements) > 0,
                        "Android did not create native path elements");
                directories.set(list, updated);
                elements.set(list, nextElements);
                String selected = ((BaseDexClassLoader) loader).findLibrary("Unreal");
                NativeUpdatePolicy.require(selected != null && new File(selected).getCanonicalFile().equals(library.getCanonicalFile()),
                        "NativeActivity and Java would select different Unreal libraries");
                return change;
            } catch (Exception | LinkageError error) {
                change.restore();
                throw error;
            }
        }

        void restore() {
            try {
                directoriesField.set(pathList, oldDirectories);
                elementsField.set(pathList, oldElements);
            } catch (Exception error) { throw new UnsafeNativePathError(error); }
        }
    }

    /** If recovery itself fails, starting any UE library in this process would be ambiguous. */
    private static final class UnsafeNativePathError extends Error {
        UnsafeNativePathError(Exception cause) { super("Cannot restore original native search path", cause); }
    }

    private static HttpURLConnection connect(String address) throws Exception {
        return connect(address, 0, "");
    }

    private static HttpURLConnection connect(String address, long offset, String etag) throws Exception {
        NativeUpdatePolicy.requireHttps(address);
        HttpURLConnection connection = (HttpURLConnection) new URL(address).openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        connection.setUseCaches(false);
        connection.setRequestProperty("Accept-Encoding", "identity");
        if (offset > 0) {
            connection.setRequestProperty("Range", "bytes=" + offset + "-");
            if (!etag.isEmpty()) connection.setRequestProperty("If-Range", etag);
        }
        try {
            int response = connection.getResponseCode();
            if (response != 200 && !(offset > 0 && response == 206)) throw new ProtocolException("Native update HTTP " + response);
            String encoding = connection.getHeaderField("Content-Encoding");
            if (encoding != null && !encoding.trim().equalsIgnoreCase("identity")) throw new ProtocolException("Encoded native response is not supported");
        } catch (Exception error) {
            connection.disconnect();
            throw error;
        }
        return connection;
    }

    private static String strongEtag(String value) throws Exception {
        if (value == null) return "";
        NativeUpdatePolicy.require(value.length() <= 512 && value.indexOf('\r') < 0 && value.indexOf('\n') < 0,
                "Invalid native response validator");
        value = value.trim();
        // Weak or unsupported validators are never sent in If-Range. The signed
        // target and final whole-file SHA remain mandatory even without ETag.
        return value.matches("\"[\\x21\\x23-\\x7E]*\"") ? value : "";
    }

    private static void clearPartial(File partial, File binding) throws Exception {
        NativeUpdatePolicy.require(!partial.exists() || (partial.isFile() && partial.delete()), "Cannot discard native partial");
        new AtomicFile(binding).delete();
        NativeUpdatePolicy.require(!binding.exists() && !new File(binding.getPath() + ".bak").exists(),
                "Cannot discard native partial binding");
    }

    private static void writePartialBinding(File binding, String target, String etag) throws Exception {
        byte[] bytes = new JSONObject().put("format", 1).put("signedEnvelopeSha256", target).put("etag", etag)
                .toString().getBytes(StandardCharsets.UTF_8);
        AtomicFile file = new AtomicFile(binding);
        FileOutputStream stream = null;
        try {
            stream = file.startWrite();
            stream.write(bytes);
            stream.getFD().sync();
            file.finishWrite(stream);
        } catch (Exception error) {
            if (stream != null) file.failWrite(stream);
            throw error;
        }
        NativeUpdatePolicy.require(Arrays.equals(bytes, read(file.openRead(), MAX_MANIFEST)),
                "Native partial binding commit did not survive readback");
    }

    private static final class ResumableDownloadException extends IOException {
        ResumableDownloadException(String message, IOException cause) { super(message, cause); }
    }

    private static void logRetainedPartial(long release, File partial) {
        Log.i(TAG, "NATIVE_DOWNLOAD_RETAIN release=" + release + " bytes=" + (partial.isFile() ? partial.length() : 0));
    }

    private static void downloadLibrary(JSONObject candidate, byte[] envelope, File destination) throws Exception {
        long size = number(candidate, "soSize");
        long release = number(candidate, "releaseId");
        File partial = NativeUpdatePolicy.child(destination.getParentFile(), "libUnreal.so.part");
        File binding = NativeUpdatePolicy.child(destination.getParentFile(), "libUnreal.so.part.json");
        File directory = destination.getParentFile().getCanonicalFile();
        for (File file : new File[] { destination, partial, binding, new File(binding.getPath() + ".bak") }) {
            NativeUpdatePolicy.require(file.getCanonicalFile().equals(new File(directory, file.getName())),
                    "Native download file is aliased");
        }
        String target = NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(envelope));
        long offset = 0;
        String etag = "";
        if (partial.exists()) {
            NativeUpdatePolicy.require(partial.isFile(), "Native partial is not a regular file");
            if (partial.length() > size) {
                clearPartial(partial, binding);
                throw new IOException("Native partial exceeds signed size");
            }
            if (binding.isFile() || new File(binding.getPath() + ".bak").isFile()) {
                JSONObject saved;
                try {
                    saved = new JSONObject(utf8(read(new AtomicFile(binding).openRead(), MAX_MANIFEST)));
                    NativeUpdatePolicy.require(number(saved, "format") == 1, "Unsupported native partial binding");
                    String validator = saved.getString("etag");
                    NativeUpdatePolicy.require(validator.isEmpty() || validator.equals(strongEtag(validator)), "Invalid saved native validator");
                    if (text(saved, "signedEnvelopeSha256").equals(target)) {
                        offset = partial.length();
                        etag = validator;
                    } else {
                        clearPartial(partial, binding);
                    }
                } catch (Exception error) {
                    // An unbound/corrupt partial is never appended or promoted.
                    // Remove it and fail this check; a later check can start clean.
                    clearPartial(partial, binding);
                    throw error;
                }
            } else {
                clearPartial(partial, binding);
            }
        }
        if (offset == size) {
            try { NativeUpdatePolicy.verifyFile(partial, size, text(candidate, "soSha256")); }
            catch (Exception error) { clearPartial(partial, binding); throw error; }
            NativeUpdatePolicy.require(partial.renameTo(destination), "Could not commit verified recovered native library");
            clearPartial(partial, binding);
            synchronized (NativeUpdate.class) { receivedBytes = size; }
            Log.i(TAG, "NATIVE_DOWNLOAD_VERIFIED release=" + release + " bytes=" + size + " recoveredCompletePartial=1");
            return;
        }
        Log.i(TAG, "NATIVE_DOWNLOAD_REQUEST release=" + release + " offset=" + offset + " total=" + size);
        synchronized (NativeUpdate.class) { receivedBytes = offset; }
        HttpURLConnection payload;
        try { payload = connect(text(candidate, "soUrl"), offset, etag); }
        catch (ProtocolException error) { clearPartial(partial, binding); throw error; }
        catch (IOException error) { logRetainedPartial(release, partial); throw error; }
        try {
            int response = payload.getResponseCode();
            String range = payload.getHeaderField("Content-Range");
            String responseEtag = strongEtag(payload.getHeaderField("ETag"));
            long expectedBytes = size;
            if (response == 206) {
                java.util.regex.Matcher match = java.util.regex.Pattern.compile("bytes ([0-9]+)-([0-9]+)/([0-9]+)")
                        .matcher(range == null ? "" : range);
                NativeUpdatePolicy.require(match.matches(), "Invalid native Content-Range");
                NativeUpdatePolicy.require(Long.parseLong(match.group(1)) == offset && Long.parseLong(match.group(2)) == size - 1
                        && Long.parseLong(match.group(3)) == size, "Native response range differs from signed target and partial");
                NativeUpdatePolicy.require(etag.isEmpty() || etag.equals(responseEtag), "Native range validator changed");
                expectedBytes = size - offset;
            } else {
                NativeUpdatePolicy.require(range == null, "Unexpected Content-Range on full native response");
            }
            long declared = payload.getContentLengthLong();
            NativeUpdatePolicy.require(declared == -1 || declared == expectedBytes, "Native HTTP size differs from signed response range");
            NativeUpdatePolicy.require(!partial.exists() || partial.length() == offset, "Native partial changed while requesting its range");
            boolean append = response == 206;
            Log.i(TAG, "NATIVE_DOWNLOAD_RESPONSE release=" + release + " code=" + response + " offset=" + offset
                    + " contentRange=" + (append ? offset + "-" + (size - 1) + "/" + size : "none")
                    + " writeOffset=" + (append ? offset : 0));
            if (!append) offset = 0; // A server may ignore Range or If-Range and return the whole signed object.
            writePartialBinding(binding, target, responseEtag);
            long received = offset;
            synchronized (NativeUpdate.class) { receivedBytes = received; }
            byte[] buffer = new byte[262144];
            InputStream source;
            try { source = payload.getInputStream(); }
            catch (ProtocolException error) { throw error; }
            catch (IOException error) { throw new ResumableDownloadException("Native response stream interrupted", error); }
            try (InputStream input = source; FileOutputStream stream = new FileOutputStream(partial, append)) {
                try {
                    while (true) {
                        int count;
                        try { count = input.read(buffer); }
                        catch (ProtocolException error) { throw error; }
                        catch (IOException error) { throw new ResumableDownloadException("Native transfer interrupted", error); }
                        if (count == -1) break;
                        if (count <= 0 || received > size - count) throw new ProtocolException("Native download exceeds signed size or made no progress");
                        stream.write(buffer, 0, count);
                        received += count;
                        synchronized (NativeUpdate.class) { receivedBytes = received; }
                    }
                } finally { stream.getFD().sync(); }
            }
            // Short EOF/timeouts retain only this signed-target-bound partial.
            // No candidate or anti-rollback state is committed before full verification.
            if (received != size) throw new ResumableDownloadException("Native download is incomplete; retry can resume", null);
            NativeUpdatePolicy.verifyFile(partial, size, text(candidate, "soSha256"));
            NativeUpdatePolicy.require(partial.renameTo(destination), "Could not commit verified native library");
            clearPartial(partial, binding);
            Log.i(TAG, "NATIVE_DOWNLOAD_VERIFIED release=" + release + " bytes=" + size + " recoveredCompletePartial=0");
        } catch (ResumableDownloadException error) {
            logRetainedPartial(release, partial);
            throw error;
        } catch (Exception error) {
            clearPartial(partial, binding);
            throw error;
        } finally { payload.disconnect(); }
    }

    public static synchronized void beginCheck() {
        if (checking || !libraryLoaded || !enabled() || root == null || publicKey == null) return;
        checking = true;
        receivedBytes = 0;
        totalBytes = 0;
        setState("Checking", "Checking signed native update manifest");
        new Thread(() -> {
            try { checkAndStage(); }
            catch (Exception error) {
                synchronized (NativeUpdate.class) { setState("UpdateFailed", error.getClass().getSimpleName() + ": " + error.getMessage()); }
            } finally {
                synchronized (NativeUpdate.class) { checking = false; }
            }
        }, "SampleGameNativeDownload").start();
    }

    private static void checkAndStage() throws Exception {
        HttpURLConnection manifest = connect(text(bootstrap, "manifestUrl"));
        byte[] envelope;
        try {
            NativeUpdatePolicy.require(manifest.getContentLengthLong() <= MAX_MANIFEST, "Manifest HTTP size exceeds limit");
            envelope = read(manifest.getInputStream(), MAX_MANIFEST);
        } finally { manifest.disconnect(); }
        JSONObject candidate = verifyEnvelope(envelope);
        long release = number(candidate, "releaseId");
        synchronized (NativeUpdate.class) {
            long highest = Math.max(Math.max(storedNumber("high-water"), storedNumber("blocked-release")), verifiedActiveRelease());
            if (release <= highest || release <= selectedRelease) {
                setState("UpToDate", "No newer acceptable native release");
                return;
            }
            totalBytes = number(candidate, "soSize");
            NativeUpdatePolicy.require(root.getUsableSpace() >= totalBytes + 64L * 1024L * 1024L, "Insufficient private storage for native update");
            setState("Downloading", "Downloading native library for the next cold start");
        }
        File destination = libraryFile(candidate);
        if (!destination.isFile()) downloadLibrary(candidate, envelope, destination);
        NativeUpdatePolicy.verifyFile(destination, totalBytes, text(candidate, "soSha256"));
        // Also protect a verified destination recovered after an interrupted prior attempt.
        protectLibrary(destination);
        synchronized (NativeUpdate.class) {
            atomicWrite(named("active.json"), envelope);
            storeNumber("high-water", release);
            readyRelease = release;
            setState("ReadyToRestart", "Native update verified; it will load on the next cold start");
        }
    }

    /** Called only after a real game world has stayed alive; downloading does not confirm startup. */
    public static synchronized void confirmStableStartup() {
        if (!candidateLoaded || selectedRelease <= 0 || root == null) return;
        try {
            JSONObject marker = bootMarker("boot-pending");
            if (marker == null) {
                JSONObject confirmed = bootMarker("boot-confirmed");
                NativeUpdatePolicy.require(confirmed != null && number(confirmed, "releaseId") == selectedRelease
                        && text(confirmed, "attemptId").equals(selectedAttempt), "No matching native startup confirmation");
                return;
            }
            NativeUpdatePolicy.require(number(marker, "releaseId") == selectedRelease
                    && text(marker, "attemptId").equals(selectedAttempt), "Native startup marker differs from loaded attempt");
            writeBootMarker("boot-confirmed", marker);
            storeNumber("confirmed-release", selectedRelease);
            deleteMetadata("boot-pending");
            if (!checking && readyRelease <= selectedRelease) setState("Active", "Native startup confirmed");
        } catch (Exception error) { setState("ConfirmationFailed", error.toString()); }
    }

    public static synchronized String statusJson() {
        JSONObject result = new JSONObject();
        try {
            result.put("platform", "Android_ARM64");
            result.put("enabled", enabled());
            result.put("state", state);
            result.put("message", message);
            result.put("loadedReleaseId", selectedRelease);
            result.put("readyReleaseId", readyRelease);
            result.put("nativeSourceHash", selectedHash);
            result.put("libraryPath", selectedPath);
            result.put("downloadedBytes", receivedBytes);
            result.put("totalBytes", totalBytes);
            result.put("restartRequired", readyRelease > selectedRelease);
            result.put("startupPending", candidateLoaded && root != null && metadataExists("boot-pending"));
        } catch (Exception error) { Log.w(TAG, "Native status serialization failed", error); }
        return result.toString();
    }
}
