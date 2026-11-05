package com.example.samplegame.update;

import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Real Java downloader with bounded HTTP/Android doubles, not a device or network test. */
public final class NativeUpdateDownloadTest {
    private static final String MANIFEST = "https://updates.example.com/manifest.json";
    private static final String SO = "https://updates.example.com/r2.so";
    private static final ArrayDeque<Reply> replies = new ArrayDeque<>();
    private static final List<Map<String, String>> requests = new ArrayList<>();
    private static KeyPair keys;
    private static File root;
    private static byte[] good;
    private static byte[] manifest;
    private static JSONObject profile;
    private static long candidateRelease;
    private static int checks;

    private static final class Reply {
        int status = 200;
        long declared;
        byte[] body;
        int failAfter = -1;
        boolean protocolFailure;
        final Map<String, String> headers = new HashMap<>();
        Reply(byte[] body, long declared) { this.body = body; this.declared = declared; }
        Reply header(String name, String value) { headers.put(name, value); return this; }
        Reply status(int value) { status = value; return this; }
        Reply length(long value) { declared = value; return this; }
    }

    interface Action { void run() throws Exception; }
    private static void check(boolean value, String name) { ++checks; if (!value) throw new AssertionError(name); }
    private static void rejects(Action action, String name) throws Exception {
        boolean failed = false;
        try { action.run(); } catch (Exception expected) { failed = true; }
        check(failed, name);
    }
    private static void set(String name, Object value) throws Exception {
        Field field = NativeUpdate.class.getDeclaredField(name); field.setAccessible(true); field.set(null, value);
    }
    private static Object invoke(String name, Class<?>[] types, Object... arguments) throws Exception {
        Method method = NativeUpdate.class.getDeclaredMethod(name, types); method.setAccessible(true);
        try { return method.invoke(null, arguments); }
        catch (InvocationTargetException error) {
            if (error.getCause() instanceof Exception) throw (Exception) error.getCause();
            throw error;
        }
    }
    private static JSONObject candidate(byte[] body) throws Exception {
        JSONObject value = new JSONObject(profile.toString()); value.remove("enabled"); value.remove("manifestUrl");
        return value.put("platform", "Android_ARM64").put("releaseId", candidateRelease).put("nativeSourceHash", "b".repeat(64))
                .put("soSha256", NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(body)))
                .put("soSize", body.length).put("soUrl", SO).put("versionLabel", "1.0.4-resume");
    }
    private static byte[] sign(JSONObject value) throws Exception {
        byte[] payload = value.toString().getBytes(StandardCharsets.UTF_8);
        Signature signature = Signature.getInstance("SHA256withRSA"); signature.initSign(keys.getPrivate()); signature.update(payload);
        return new JSONObject().put("format", 1).put("signatureAlgorithm", "SHA256withRSA")
                .put("payloadBase64", Base64.getEncoder().encodeToString(payload))
                .put("signatureBase64", Base64.getEncoder().encodeToString(signature.sign())).toString().getBytes(StandardCharsets.UTF_8);
    }
    private static File destination() throws Exception {
        return (File) invoke("libraryFile", new Class<?>[] { JSONObject.class }, candidate(good));
    }
    private static File partial() throws Exception { return new File(destination().getParentFile(), "libUnreal.so.part"); }
    private static File binding() throws Exception { return new File(destination().getParentFile(), "libUnreal.so.part.json"); }
    private static void stage() throws Exception { invoke("checkAndStage", new Class<?>[0]); }
    private static void clean() throws Exception {
        if (root != null) {
            try (var paths = Files.walk(root.toPath())) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { path.toFile().setWritable(true); Files.delete(path); } catch (Exception error) { throw new RuntimeException(error); }
                });
            }
        }
        root = Files.createTempDirectory("native-range-test-").toFile();
        set("root", root); set("bootstrap", profile); set("publicKey", keys.getPublic());
        set("selectedRelease", 0L); set("readyRelease", 0L); set("receivedBytes", 0L); set("totalBytes", 0L);
        replies.clear(); requests.clear(); candidateRelease = 401; manifest = sign(candidate(good));
    }
    private static Reply full(byte[] body) { return new Reply(body, good.length).header("ETag", "\"one\""); }
    private static Reply range(int start) {
        return new Reply(Arrays.copyOfRange(good, start, good.length), good.length - start).status(206)
                .header("Content-Range", "bytes " + start + "-" + (good.length - 1) + "/" + good.length).header("ETag", "\"one\"");
    }
    private static void interrupted(int bytes) throws Exception {
        replies.add(full(Arrays.copyOf(good, bytes)));
        rejects(NativeUpdateDownloadTest::stage, "Short transfer fails without activation");
        check(partial().length() == bytes && binding().isFile(), "Bound partial survives short EOF");
        check(!new File(root, "active.json").exists() && !new File(root, "high-water").exists(), "Partial never commits selection or anti-rollback metadata");
    }
    private static void activated() throws Exception {
        check(Arrays.equals(Files.readAllBytes(destination().toPath()), good), "Whole downloaded object equals expected signed SO");
        check(!destination().canWrite(), "Verified complete SO is read-only before activation");
        check(!partial().exists() && !binding().exists(), "Committed candidate leaves no partial or binding");
        check(new File(root, "active.json").isFile() && new File(root, "high-water").isFile(), "Only complete verified download commits activation");
    }

    public static void main(String[] arguments) throws Exception {
        URL.setURLStreamHandlerFactory(protocol -> protocol.equals("https") ? new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL url) {
                Reply reply = url.toString().equals(MANIFEST) ? new Reply(manifest, manifest.length) : replies.removeFirst();
                return new HttpURLConnection(url) {
                    private boolean recorded;
                    @Override public int getResponseCode() {
                        if (!recorded && !url.toString().equals(MANIFEST)) {
                            Map<String, String> request = new HashMap<>();
                            for (String name : new String[] { "Range", "If-Range", "Accept-Encoding" }) request.put(name, getRequestProperty(name));
                            requests.add(request); recorded = true;
                        }
                        return reply.status;
                    }
                    @Override public String getHeaderField(String name) { return reply.headers.get(name); }
                    @Override public long getContentLengthLong() { return reply.declared; }
                    @Override public InputStream getInputStream() {
                        if (reply.failAfter < 0) return new ByteArrayInputStream(reply.body);
                        return new InputStream() {
                            int index;
                            @Override public int read() throws IOException { byte[] one = new byte[1]; return read(one, 0, 1) < 0 ? -1 : one[0] & 255; }
                            @Override public int read(byte[] target, int offset, int count) throws IOException {
                                if (index >= reply.failAfter) {
                                    if (reply.protocolFailure) throw new java.net.ProtocolException("Injected malformed transfer");
                                    throw new java.net.SocketTimeoutException("Injected timeout");
                                }
                                int copied = Math.min(count, Math.min(reply.body.length - index, reply.failAfter - index));
                                if (copied <= 0) return -1;
                                System.arraycopy(reply.body, index, target, offset, copied); index += copied; return copied;
                            }
                        };
                    }
                    @Override public void disconnect() { }
                    @Override public boolean usingProxy() { return false; }
                    @Override public void connect() { }
                };
            }
        } : null);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); keys = generator.generateKeyPair();
        ByteBuffer elf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN);
        elf.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, 1, 1 }).position(16);
        elf.putShort((short)3).putShort((short)183).putInt(1).putLong(0).putLong(64).putLong(0).putInt(0);
        elf.putShort((short)64).putShort((short)56).putShort((short)1).position(64);
        elf.putInt(1).putInt(5).putLong(0).putLong(0).putLong(0).putLong(1024).putLong(1024).putLong(16384); good = elf.array();
        profile = new JSONObject().put("format", 1).put("enabled", true).put("packageName", "com.example.samplegame")
                .put("channel", "range-host-only").put("baseReleaseId", 400).put("baseNativeSourceHash", "a".repeat(64))
                .put("nativeApiVersion", 2).put("engineBuildId", "host-test").put("abi", "arm64-v8a")
                .put("manifestUrl", MANIFEST).put("contentCompatibilityId", "host-test-only");
        try {
            clean(); replies.add(full(good)); stage(); activated();
            check(requests.get(0).get("Range") == null && requests.get(0).get("Accept-Encoding").equals("identity"), "Fresh download requests unencoded whole object");
            clean(); interrupted(128); replies.add(range(128)); stage(); activated();
            check(requests.get(1).get("Range").equals("bytes=128-") && requests.get(1).get("If-Range").equals("\"one\""), "Resume uses actual partial length and strong If-Range");

            clean(); interrupted(128); Reply timeout = range(128); timeout.failAfter = 100; replies.add(timeout);
            rejects(NativeUpdateDownloadTest::stage, "Mid-range timeout preserves download");
            check(partial().length() == 228, "Repeated interruption advances actual saved partial length");
            replies.add(range(228)); stage(); activated();
            check(requests.get(2).get("Range").equals("bytes=228-"), "Second resume starts from new on-disk length");

            clean(); Reply malformedStream = full(good); malformedStream.failAfter = 128; malformedStream.protocolFailure = true; replies.add(malformedStream);
            rejects(NativeUpdateDownloadTest::stage, "Body protocol failure is not a resumable network timeout");
            check(!partial().exists() && !binding().exists(), "Malformed transfer discards partial and binding");

            clean(); interrupted(128); replies.add(full(good).header("ETag", "\"new\"")); stage(); activated();
            check(requests.get(1).get("Range").equals("bytes=128-"), "Ignored Range200 safely restarts whole object");
            for (String bad : new String[] { "bytes 127-1023/1024", "bytes 128-1022/1024", "bytes 128-1023/2048", "bytes 128-1023/*", "bytes 128-1023/1024,0-1/1024", "bytes 999999999999999999999999-1023/1024", "" }) {
                clean(); interrupted(128); replies.add(range(128).header("Content-Range", bad));
                rejects(NativeUpdateDownloadTest::stage, "Wrong/malformed Content-Range rejected");
                check(!partial().exists() && !binding().exists() && !new File(root, "active.json").exists(), "Bad range discards unsafe transfer without activation");
            }
            for (Reply bad : new Reply[] { range(128).header("ETag", "\"changed\""), range(128).header("ETag", null),
                    range(128).header("Content-Encoding", "gzip"), range(128).length(good.length), range(128).status(416), range(128).status(302),
                    full(good).header("Content-Range", "bytes 0-1023/1024"), new Reply(good, 5) }) {
                clean(); interrupted(128); replies.add(bad); rejects(NativeUpdateDownloadTest::stage, "Bad validator/encoding/status/length rejected");
                check(!partial().exists() && !binding().exists() && !new File(root, "active.json").exists(), "Invalid response is not retained as a resumable transfer");
            }
            clean(); replies.add(range(128)); rejects(NativeUpdateDownloadTest::stage, "Unsolicited206 rejected on fresh request");
            check(!new File(root, "active.json").exists(), "Fresh206 never activates");
            clean(); interrupted(128); Reply chunked = range(128); chunked.declared = -1; replies.add(chunked); stage(); activated();

            clean(); interrupted(128); byte[] prefix = Files.readAllBytes(partial().toPath()); prefix[0] ^= 1; Files.write(partial().toPath(), prefix);
            replies.add(range(128)); rejects(NativeUpdateDownloadTest::stage, "Tampered partial rejected by whole signed SHA");
            check(!partial().exists() && !binding().exists() && !new File(root, "active.json").exists(), "Corrupt complete result discarded without activation");
            replies.add(full(good)); stage(); activated(); check(requests.get(2).get("Range") == null, "Whole SHA failure can recover through clean full download");
            clean(); Reply overflow = full(Arrays.copyOf(good, good.length + 1)); replies.add(overflow);
            rejects(NativeUpdateDownloadTest::stage, "Actual body over signed bound rejected");
            check(!partial().exists() && !binding().exists(), "Oversized transfer discarded");

            clean(); File unbound = partial(); Files.write(unbound.toPath(), Arrays.copyOf(good, 128)); replies.add(full(good)); stage(); activated();
            check(requests.get(0).get("Range") == null, "Unbound old partial never resumed");
            clean(); interrupted(128); manifest = sign(candidate(good).put("versionLabel", "changed-signed-target")); replies.add(full(good)); stage(); activated();
            check(requests.get(1).get("Range") == null, "Different signed envelope discards old binding and starts clean");
            clean(); interrupted(128); Files.writeString(binding().toPath(), "invalid-json");
            rejects(NativeUpdateDownloadTest::stage, "Corrupt partial metadata fails closed");
            check(!partial().exists() && !binding().exists() && requests.size() == 1, "Corrupt binding removed before any payload request");

            clean(); Reply completedBeforeTimeout = full(good); completedBeforeTimeout.failAfter = good.length; replies.add(completedBeforeTimeout);
            rejects(NativeUpdateDownloadTest::stage, "Interrupted after all bytes, before EOF, leaves bound complete partial");
            check(partial().length() == good.length, "Complete partial retained after transport interruption");
            stage(); activated(); check(requests.size() == 1, "Complete bound partial verified without duplicate payload request");
            clean(); Reply corruptComplete = full(good); corruptComplete.failAfter = good.length; replies.add(corruptComplete);
            rejects(NativeUpdateDownloadTest::stage, "Bound full partial prepared before EOF");
            byte[] changedComplete = Files.readAllBytes(partial().toPath()); changedComplete[0] ^= 1; Files.write(partial().toPath(), changedComplete);
            rejects(NativeUpdateDownloadTest::stage, "Complete-size partial must pass whole SHA before reuse, not request Range416");
            check(requests.size() == 1 && !partial().exists(), "Invalid complete partial discarded before HTTP");
            replies.add(full(good)); stage(); activated();

            clean(); Reply noValidator = full(Arrays.copyOf(good, 128)).header("ETag", null); replies.add(noValidator);
            rejects(NativeUpdateDownloadTest::stage, "Short response without ETag remains signed-target bound");
            replies.add(range(128).header("ETag", null)); stage(); activated();
            check(requests.get(1).get("Range").equals("bytes=128-") && requests.get(1).get("If-Range") == null, "Missing optional ETag never weakens signed whole-file verification");
            clean(); interrupted(128); check(binding().renameTo(new File(binding().getPath() + ".bak")), "Atomic partial binding backup prepared");
            replies.add(range(128)); stage(); activated(); check(requests.get(1).get("Range").equals("bytes=128-"), "Atomic binding backup recovers original signed partial identity");
            clean(); File tooLong = partial(); Files.write(tooLong.toPath(), new byte[good.length + 1]);
            rejects(NativeUpdateDownloadTest::stage, "Local partial over signed size rejected before HTTP");
            check(!partial().exists() && requests.isEmpty(), "Oversized partial discarded without requesting invalid Range");

            clean(); interrupted(128); replies.add(range(128)); AtomicFile.failFinishName = "libUnreal.so.part.json";
            rejects(NativeUpdateDownloadTest::stage, "Local partial binding commit failure fails closed");
            check(!partial().exists() && !binding().exists() && !new File(root, "active.json").exists(), "Local commit error is not retained as a network interruption");
            replies.add(full(good)); stage(); activated();

            clean(); File reference = new File(partial().getParentFile(), "reference.bin"); Files.write(reference.toPath(), Arrays.copyOf(good, 128));
            boolean aliasesSupported = true;
            try { Files.createSymbolicLink(partial().toPath(), reference.toPath().getFileName()); }
            catch (UnsupportedOperationException | java.nio.file.FileSystemException unavailable) { aliasesSupported = false; }
            if (aliasesSupported) {
                replies.add(full(good)); rejects(NativeUpdateDownloadTest::stage, "Same-directory partial symlink rejected by canonical filename guard");
                check(reference.length() == 128 && requests.isEmpty(), "Aliased partial cannot modify referenced file or request payload");
                clean(); File version = destination().getParentFile(); File alias = new File(root, "different-version"); check(alias.mkdir() && version.delete(), "Version alias fixture prepared");
                Files.createSymbolicLink(version.toPath(), alias.toPath().getFileName()); replies.add(full(good));
                rejects(NativeUpdateDownloadTest::stage, "Same-private-root version-directory alias rejected");
                check(requests.isEmpty(), "Aliased version never starts transfer");
                clean(); File cached = destination(); File other = new File(cached.getParentFile(), "different.so"); Files.write(other.toPath(), good);
                Files.createSymbolicLink(cached.toPath(), other.toPath().getFileName());
                rejects(NativeUpdateDownloadTest::stage, "Aliased existing complete SO rejected before cached-file shortcut");
                check(requests.isEmpty() && !new File(root, "active.json").exists(), "Valid bytes through wrong canonical filename cannot activate");
            } else {
                System.out.println("NativeUpdateDownloadTest: host symlink cases unavailable (OS privilege); canonical guards still require device validation");
            }

            clean(); byte[] badElf = good.clone(); badElf[18] = 62; manifest = sign(candidate(badElf)); replies.add(full(badElf));
            rejects(NativeUpdateDownloadTest::stage, "Signed but incompatible ELF rejected after whole SHA");
            check(!new File(root, "active.json").exists(), "Invalid ELF never activates");
            candidateRelease = 402; manifest = sign(candidate(good)); replies.add(full(good)); stage(); activated();
            check(new String(Files.readAllBytes(new File(root, "high-water").toPath()), StandardCharsets.UTF_8).equals("402"), "Higher signed valid release can recover after ELF failure");
            clean(); interrupted(128); JSONObject corrupt = new JSONObject(new String(manifest, StandardCharsets.UTF_8));
            corrupt.put("signatureBase64", Base64.getEncoder().encodeToString(new byte[256])); manifest = corrupt.toString().getBytes(StandardCharsets.UTF_8);
            rejects(NativeUpdateDownloadTest::stage, "Bad current signature rejected before resuming");
            check(partial().length() == 128 && requests.size() == 1, "Unauthenticated manifest cannot touch partial or request payload");

            clean(); interrupted(128); Files.writeString(new File(root, "blocked-release").toPath(), "401"); stage();
            check(requests.size() == 1 && partial().length() == 128 && !new File(root, "active.json").exists(), "Blocked candidate never resumes or activates");
            clean(); replies.add(full(good)); AtomicFile.failFinishName = "active.json";
            rejects(NativeUpdateDownloadTest::stage, "Activation fault after complete download fails closed");
            check(!new File(root, "active.json").exists() && !new File(root, "high-water").exists(), "Failed active commit cannot advance high-water");
            stage(); activated(); check(requests.size() == 1, "Retry reuses fully verified destination after activation fault");
        } finally {
            if (root != null) {
                try (var paths = Files.walk(root.toPath())) {
                    paths.sorted(Comparator.reverseOrder()).forEach(path -> { try { path.toFile().setWritable(true); Files.delete(path); } catch (Exception error) { throw new RuntimeException(error); } });
                }
            }
        }
        System.out.println("NativeUpdateDownloadTest: " + checks + " checks passed (host doubles; not Android/network acceptance)");
    }
}
