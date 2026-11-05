package com.example.samplegame.update;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.res.AssetManager;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Actual RSA/JKS, ZIP and filesystem transactions with Android/TLS API doubles; no device or SO execution. */
public final class ReleasePlayerHostTest {
    private static int checks, libraryLoads, requests;
    private static PrivateKey privateKey;
    private static Certificate certificate;
    private static File evidence;
    private static Activity currentGameActivity;
    private static final Map<String, Response> responses = Collections.synchronizedMap(new HashMap<>());
    private static final String ENDPOINT = "https://updates.example.com/samplegame/v106-test/updates/manifest.json";
    private interface Action { void run() throws Exception; }
    private static void check(boolean value, String label) { ++checks; if (!value) throw new AssertionError(label); }
    private static void rejects(Action action, String label) throws Exception {
        boolean rejected = false; try { action.run(); } catch (Exception error) { rejected = true; }
        check(rejected, label);
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] raw(JSONObject value) throws Exception { return bytes(ReleasePlayer.canonical(value)); }
    private static Object field(String name) throws Exception { Field field = ReleasePlayer.class.getDeclaredField(name); field.setAccessible(true); return field.get(null); }
    private static void field(String name, Object value) throws Exception { Field field = ReleasePlayer.class.getDeclaredField(name); field.setAccessible(true); field.set(null, value); }
    private static ReleaseSet.Store store() throws Exception { return (ReleaseSet.Store) field("store"); }
    private static void reset() throws Exception {
        if (store() != null) store().close();
        for (String name : new String[]{"store", "config", "selected", "ticket", "verifier", "root", "ticketFile"}) field(name, null);
        for (String name : new String[]{"preparationAttempted", "prepared", "loadAttempted", "libraryLoaded", "confirmed", "checking"}) field(name, false);
        for (String name : new String[]{"readyRelease", "downloadedBytes", "totalBytes"}) field(name, 0L);
        field("state", "NotInitialized"); field("message", ""); field("qaArguments", "");
        java.lang.reflect.Method publish = ReleasePlayer.class.getDeclaredMethod("publishStatus"); publish.setAccessible(true);
        synchronized (ReleasePlayer.class) { publish.invoke(null); }
        ReleasePlayer.libraryLoader = (loader, library) -> {
            ++libraryLoads; check(library.isFile(), "Fake native loader receives a real verified file");
        };
    }

    private static byte[] elf(int marker) {
        ByteBuffer buffer = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(new byte[]{0x7f, 'E', 'L', 'F', 2, 1, 1}); buffer.position(16);
        buffer.putShort((short) 3).putShort((short) 183).putInt(1); buffer.position(32); buffer.putLong(64);
        buffer.position(52); buffer.putShort((short) 64).putShort((short) 56).putShort((short) 1);
        buffer.position(64); buffer.putInt(1).putInt(5).putLong(0).putLong(0).putLong(0).putLong(512).putLong(512).putLong(16384);
        buffer.position(200); buffer.putInt(marker); return buffer.array();
    }

    private static JSONObject manifest(long release) throws Exception {
        JSONArray records = new JSONArray();
        byte[] pak = bytes("paired-pak-" + release), so = elf((int) release);
        records.put(new JSONObject().put("path", "Content/Paks/r" + release + "_SampleGame-Android.pak").put("role", "content").put("size", pak.length).put("sha256", ReleaseTransport.hash(pak)));
        records.put(new JSONObject().put("path", "libUnreal.so").put("role", "native").put("size", so.length).put("sha256", ReleaseTransport.hash(so)));
        JSONObject save = new JSONObject().put("schema", 1).put("readable", new JSONArray().put(0).put(1))
                .put("migrations", new JSONArray().put(new JSONObject().put("from", 0).put("to", 1).put("id", "colalab-v0-to-v1")));
        JSONObject value = new JSONObject().put("format", 1).put("kind", "samplegame-release-set").put("projectId", "SampleGame")
                .put("platform", "Android_ARM64").put("channel", "v106-test").put("baseReleaseId", 100)
                .put("engineBuildId", "engine-build").put("shellCompatibilityId", "a".repeat(64)).put("releaseId", release)
                .put("minLoaderVersion", 1).put("sourceCommit", "b".repeat(40)).put("nativeSourceHash", (release == 100 ? "c" : "d").repeat(64))
                .put("files", records).put("save", save);
        value.put("buildId", ReleaseSet.buildId(value)); return value;
    }

    private static JSONObject config(JSONObject base) throws Exception {
        JSONObject trust = new JSONObject();
        for (String name : new String[]{"projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId"}) trust.put(name, base.get(name));
        trust.put("loaderVersion", 1).put("baseManifestSha256", ReleaseTransport.hash(bytes(ReleaseSet.canonical(base))));
        JSONArray entries = new JSONArray()
                .put(new JSONObject().put("path", "libUnreal.so").put("apkPath", "lib/arm64-v8a/libUnreal.so").put("obbPath", ""))
                .put(new JSONObject().put("path", base.getJSONArray("files").getJSONObject(0).getString("path"))
                        .put("apkPath", "assets/main.obb.png").put("obbPath", "SampleGame/Content/Paks/SampleGame-Android.pak"));
        return new JSONObject().put("format", 1).put("trust", trust).put("packageName", "com.example.samplegame")
                .put("manifestUrl", ENDPOINT).put("allowOffline", true).put("signatureAlgorithm", "SHA256withRSA")
                .put("certificateBase64", java.util.Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .put("certificateSha256", ReleaseTransport.hash(certificate.getEncoded())).put("baseArchiveEntries", entries);
    }

    private static byte[] zip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try (ZipOutputStream output = new ZipOutputStream(result)) {
            for (String name : entries.keySet()) { output.putNextEntry(new ZipEntry(name)); output.write(entries.get(name)); output.closeEntry(); }
        }
        return result.toByteArray();
    }
    private static File apk(File folder, JSONObject config, JSONObject base, boolean corrupt) throws Exception {
        Map<String, byte[]> obb = new HashMap<>(); obb.put("SampleGame/Content/Paks/SampleGame-Android.pak", bytes(corrupt ? "wrong" : "paired-pak-100"));
        obb.put("SampleGame/Unrelated.txt", bytes("ignored ordinary APK asset"));
        Map<String, byte[]> outer = new HashMap<>(); outer.put("assets/main.obb.png", zip(obb)); outer.put("lib/arm64-v8a/libUnreal.so", elf(100));
        outer.put("assets/release-player.json", raw(config)); outer.put("assets/release-base-manifest.json", bytes(ReleaseSet.canonical(base)));
        File result = new File(folder, "fixture.apk"); Files.write(result.toPath(), zip(outer)); return result;
    }

    private static final class TestActivity extends Activity {
        final File directory, apk;
        TestActivity(String name, JSONObject config, JSONObject base, boolean corrupt) throws Exception {
            directory = new File(evidence, name).getCanonicalFile(); check(directory.mkdirs(), "Create independent host installation");
            apk = apk(directory, config, base, corrupt);
        }
        @Override public AssetManager getAssets() {
            return new AssetManager() {
                @Override public InputStream open(String name) {
                    try (ZipFile archive = new ZipFile(apk)) {
                        return new ByteArrayInputStream(archive.getInputStream(archive.getEntry("assets/" + name)).readAllBytes());
                    } catch (Exception error) { throw new IllegalStateException(error); }
                }
            };
        }
        private File directory(String name) { File output = new File(directory, name); output.mkdirs(); return output; }
        @Override public File getDir(String name, int mode) { return directory("private/" + name); }
        @Override public File getFilesDir() { return directory("files"); }
        @Override public File getExternalFilesDir(String type) { return directory("external"); }
        @Override public ApplicationInfo getApplicationInfo() { ApplicationInfo value = new ApplicationInfo(); value.sourceDir = apk.getPath(); return value; }
    }

    private static final class Response {
        byte[] body; int status = 200; long declared; String encoding;
        Response(byte[] value) { body = value; declared = value.length; }
    }
    private static final class Connection extends HttpsURLConnection {
        final Response response;
        Connection(URL url) { super(url); ++requests; Response selected = responses.get(url.toString()); response = selected == null ? new Response(new byte[]{1}) : selected; if (selected == null) response.status = 404; }
        @Override public int getResponseCode() { return response.status; }
        @Override public long getContentLengthLong() { return response.declared; }
        @Override public String getHeaderField(String name) { return "Content-Encoding".equalsIgnoreCase(name) ? response.encoding : null; }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(response.body); }
        @Override public String getCipherSuite() { return "HOST_TEST_DOUBLE"; }
        @Override public Certificate[] getLocalCertificates() { return null; }
        @Override public Certificate[] getServerCertificates() { return new Certificate[]{certificate}; }
        @Override public void disconnect() {}
        @Override public boolean usingProxy() { return false; }
        @Override public void connect() {}
    }

    private static void serve(JSONObject manifest) throws Exception {
        byte[] raw = bytes(ReleaseSet.canonical(manifest)); Signature signer = Signature.getInstance("SHA256withRSA"); signer.initSign(privateKey); signer.update(raw);
        responses.put(ENDPOINT, new Response(raw)); responses.put(ENDPOINT + ".sig", new Response(signer.sign()));
        long release = manifest.getLong("releaseId");
        String prefix = ENDPOINT.substring(0, ENDPOINT.lastIndexOf('/') + 1) + "versions/" + release + "/payload/";
        responses.put(prefix + "libUnreal.so", new Response(elf((int) release)));
        responses.put(prefix + "Content/Paks/r" + release + "_SampleGame-Android.pak", new Response(bytes("paired-pak-" + release)));
    }
    private static void awaitCheck() throws Exception {
        long end = System.nanoTime() + 10L * 1000000000;
        while (new JSONObject(ReleasePlayer.statusJson()).getBoolean("checking") && System.nanoTime() < end) Thread.sleep(10);
        check(!new JSONObject(ReleasePlayer.statusJson()).getBoolean("checking"), "Background check completes in host fixture deadline");
    }
    private static JSONObject acknowledgement() throws Exception {
        JSONObject ticket = new JSONObject(ReleasePlayer.selectionJson()), ack = new JSONObject();
        for (String name : new String[]{"format", "attemptId", "releaseId", "manifestSha256", "buildId", "saveSchema", "userRoot"}) ack.put(name, ticket.get(name));
        return ack.put("pid", android.os.Process.myPid()).put("luaVersion", "1.0.6");
    }
    private static void prepareLoad(TestActivity activity) throws Exception {
        ReleasePlayer.prepareForLaunch(activity);
        currentGameActivity = new Activity();
        currentGameActivity.getIntent().putExtra("cmdline", ReleasePlayer.launchArguments());
        // Model GameActivity's early getExtras() copy before its UPL LoadLibraries hook.
        String cachedBeforeNativeLoad = currentGameActivity.getIntent().getStringExtra("cmdline");
        ReleasePlayer.loadUnreal(currentGameActivity, ReleasePlayerHostTest.class.getClassLoader());
        check(cachedBeforeNativeLoad.equals(ReleasePlayer.launchArguments())
                && cachedBeforeNativeLoad.equals(currentGameActivity.getIntent().getStringExtra("cmdline")),
                "The complete validated command line exists before native loading and loadUnreal never rewrites a stale extras snapshot");
    }
    private static void confirm(String version) throws Exception { check(ReleasePlayer.acknowledge(acknowledgement().put("luaVersion", version).toString()), "Exact real-process-style identity confirms host fixture including SemVer metadata"); awaitCheck(); }
    private static void confirm() throws Exception { confirm("1.0.6"); }

    private static void createSigner() throws Exception {
        File keystore = new File(evidence, "test-signer.jks"); String password = "host-fixture-only-password";
        String keytool = new File(System.getProperty("java.home"), "bin/keytool.exe").getPath();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-keystore", keystore.getPath(), "-storetype", "JKS", "-storepass", password,
                "-keypass", password, "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=ReleasePlayer Host Fixture", "-noprompt")
                .redirectErrorStream(true).redirectOutput(new File(evidence, "test-keytool.log")).start();
        check(process.waitFor() == 0, "Create an actual temporary RSA signer; never read release private keys");
        KeyStore store = KeyStore.getInstance("JKS"); try (InputStream input = Files.newInputStream(keystore.toPath())) { store.load(input, password.toCharArray()); }
        privateKey = (PrivateKey) store.getKey("fixture", password.toCharArray()); certificate = store.getCertificate("fixture");
    }

    public static void main(String[] args) throws Exception {
        evidence = new File(args[0]).getCanonicalFile(); check(!evidence.exists() && evidence.mkdirs(), "Use fresh host evidence directory");
        createSigner(); URL.setURLStreamHandlerFactory(protocol -> "https".equals(protocol) ? new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL url) { return new Connection(url); }
        } : null);
        JSONObject base = manifest(100), target = manifest(101), bootstrap = config(base);
        JSONObject initialStatus = new JSONObject(ReleasePlayer.statusJson());
        check("NotInitialized".equals(initialStatus.getString("state")) && !initialStatus.getBoolean("checking")
                && !initialStatus.getBoolean("startupPending") && !initialStatus.getBoolean("restartRequired"), "Class initialization publishes a complete, idle status snapshot before any preparation");
        ReleasePlayer.configuration(raw(bootstrap)); check(true, "Actual X509 release pin parsed independently of installed signer");
        JSONObject wrongCertificate = new JSONObject(bootstrap.toString()).put("certificateSha256", "0".repeat(64));
        rejects(() -> ReleasePlayer.configuration(raw(wrongCertificate)), "Reject substituted release certificate");
        byte[] configRaw = raw(bootstrap); String duplicate = new String(configRaw, StandardCharsets.UTF_8);
        rejects(() -> ReleasePlayer.configuration(bytes(duplicate.substring(0, duplicate.length() - 1) + ",\"format\":1}")), "Reject duplicate bootstrap JSON key");
        for (String endpoint : new String[]{"http://updates.example.com/manifest.json", ENDPOINT + "?x=1", "https://u:p@updates.example.com/manifest.json", "https://updates.example.com/a/%2e%2e/manifest.json", "https://updates.example.com/a/../manifest.json"})
            rejects(() -> new ReleaseTransport(endpoint), "Reject unsafe endpoint: " + endpoint);
        ReleaseTransport transport = new ReleaseTransport(ENDPOINT);
        rejects(() -> transport.artifact("../escape"), "Artifact cannot escape channel");
        JSONObject noPrefix = new JSONObject(target.toString()); noPrefix.getJSONArray("files").getJSONObject(0).put("path", "Content/Paks/SampleGame-Android.pak");
        rejects(() -> ReleasePlayer.manifestPolicy(noPrefix), "Reject a PAK basename that could remount APK content");

        reset(); TestActivity healthy = new TestActivity("healthy", bootstrap, base, false);
        File legacy = new File(healthy.getExternalFilesDir(null), "UnrealGame/SampleGame/SampleGame/Saved/SaveGames/ColaLabQuickSave.sav");
        legacy.getParentFile().mkdirs(); Files.write(legacy.toPath(), bytes("historical-save-bytes"));
        File oldConfig = new File(healthy.getExternalFilesDir(null), "UnrealGame/SampleGame/SampleGame/Saved/Config/Android/GameUserSettings.ini");
        oldConfig.getParentFile().mkdirs(); Files.write(oldConfig.toPath(), bytes("[GameSettings]\nSavedSetting=1\n"));
        File cache = new File(healthy.getExternalFilesDir(null), "UnrealGame/SampleGame/SampleGame/Saved/Logs/huge.log"); cache.getParentFile().mkdirs(); Files.write(cache.toPath(), bytes("cache-not-imported"));
        healthy.getIntent().putExtra("cmdline", "-SampleGameSkipBoot -SampleGameBootExitAfterMenu=5 -SampleGameMenuProbe -SampleGameExpectedContentVersion=1.0.6+hotfix.1");
        serve(base); int beforeNetwork = requests, beforeLoad = libraryLoads;
        ReleasePlayer.checkForUpdates(); check(requests == beforeNetwork, "An unprepared process cannot start update requests");
        prepareLoad(healthy);
        JSONObject pendingStatus = new JSONObject(ReleasePlayer.statusJson());
        check(pendingStatus.getBoolean("startupPending") && pendingStatus.getLong("loadedReleaseId") == 100
                && !pendingStatus.getBoolean("checking") && pendingStatus.getBoolean("enabled"), "Successful native load immediately publishes pending startup without waiting for a later setState");
        check(requests == beforeNetwork, "Cold start verifies local files without blocking on network");
        check(libraryLoads == beforeLoad + 1, "Exactly one loader invocation selects the verified native library");
        JSONObject selected = new JSONObject(ReleasePlayer.selectionJson());
        File selectedSaves = new File(selected.getString("userRoot"));
        check(Arrays.equals(Files.readAllBytes(new File(selectedSaves, "Saved/SaveGames/ColaLabQuickSave.sav").toPath()), Files.readAllBytes(legacy.toPath())), "Import exact historical save bytes into selected private generation");
        check(!new File(selectedSaves, "Saved/Logs").exists() && legacy.isFile(), "Import only SaveGames/Config; preserve original user data");
        check(Arrays.equals(Files.readAllBytes(new File(selectedSaves, "Saved/Config/Android/GameUserSettings.ini").toPath()), Files.readAllBytes(oldConfig.toPath())), "Preserve authored user settings together with save bytes");
        check(new String(Files.readAllBytes(new File(new File(selected.getString("ackPath")).getParentFile(), "ticket.json").toPath()), StandardCharsets.UTF_8).equals(ReleasePlayer.selectionJson()), "JNI selection exactly matches ticket bytes");
        String arguments = currentGameActivity.getIntent().getStringExtra("cmdline");
        check(arguments.contains("-paklist=r100_SampleGame-Android") && arguments.contains("-UserDir=\"") && arguments.contains("-SampleGameReleaseTicket=\"") && arguments.contains("-SampleGameMenuProbe"), "Fixed selected PAK/save/ticket routes precede whitelist QA flags");
        check(arguments.contains("-SampleGameExpectedContentVersion=1.0.6+hotfix.1"), "Whitelist preserves bounded SemVer build metadata for the native candidate version probe");
        rejects(() -> ReleasePlayer.arguments(selected, base, new File(evidence, "ticket.json"), "-pakdir=/evil"), "Reject independent PAK override");
        rejects(() -> ReleasePlayer.arguments(selected, base, new File(evidence, "ticket.json"), "-SampleGameSkipBoot -SampleGameSkipBoot"), "Reject duplicate QA options");
        rejects(() -> ReleasePlayer.arguments(selected, base, new File(evidence, "ticket.json"), "-SampleGameExpectedContentVersion=1.0.6+bad..metadata"), "Reject malformed SemVer metadata");
        rejects(() -> ReleasePlayer.arguments(selected, base, new File(evidence, "ticket.json"), "-SampleGameMenuExpectedContentVersion=1.0.6+hotfix.1"), "Reject a misspelled probe option that the native version check does not consume");
        ReleasePlayer.loadUnreal(currentGameActivity, ReleasePlayerHostTest.class.getClassLoader()); check(libraryLoads == beforeLoad + 1, "Repeated UPL load cannot select or load another library");
        JSONObject wrongPid = acknowledgement().put("pid", 4321);
        check(!ReleasePlayer.acknowledge(wrongPid.toString()), "Reject health from a different PID");
        check(!store().state().isNull("boot") && requests == beforeNetwork, "Invalid health leaves startup pending and does not trigger network");
        JSONObject wrongBuild = acknowledgement().put("buildId", "0".repeat(64));
        check(!ReleasePlayer.acknowledge(wrongBuild.toString()) && !store().state().isNull("boot"), "A matching PID cannot confirm the wrong native/content build identity");
        check(!ReleasePlayer.acknowledge(acknowledgement().put("luaVersion", "1.0.6+").toString()) && !store().state().isNull("boot"), "Malformed Lua version cannot erase pending health state");
        confirm("1.0.6+hotfix.1"); check(store().state().isNull("boot"), "Valid SemVer metadata health durably confirms only the current set");
        check(!ReleasePlayer.acknowledge(acknowledgement().toString()), "Reject replayed health acknowledgement");
        serve(target); Response validSignature = responses.get(ENDPOINT + ".sig"); responses.put(ENDPOINT + ".sig", new Response(new byte[256]));
        int beforeConcurrentCheck = requests;
        synchronized (ReleasePlayer.class) {
            ReleasePlayer.checkForUpdates();
            String checkingSnapshot = ReleasePlayer.statusJson();
            FutureTask<String> observer = new FutureTask<>(() -> {
                String snapshot = ReleasePlayer.statusJson(); ReleasePlayer.checkForUpdates(); return snapshot;
            });
            Thread reader = new Thread(observer, "HostGameThreadStatusProbe"); reader.setDaemon(true); reader.start();
            String observed = observer.get(1, TimeUnit.SECONDS);
            check(observed.equals(checkingSnapshot) && new JSONObject(observed).getBoolean("checking")
                    && "Checking".equals(new JSONObject(observed).getString("state")), "Status and a duplicate update request complete on another thread while the real transaction monitor remains held");
        }
        awaitCheck();
        check(requests == beforeConcurrentCheck + 2, "Concurrent duplicate update request starts no additional manifest or signature transfer");
        check("UpdateFailed".equals(new JSONObject(ReleasePlayer.statusJson()).getString("state"))
                && !new JSONObject(ReleasePlayer.statusJson()).getBoolean("checking")
                && !new JSONObject(ReleasePlayer.statusJson()).getBoolean("startupPending")
                && store().state().getLong("highestReleaseId") == 100, "Wrong signature publishes failure and cleared checking without changing the confirmed generation");
        responses.put(ENDPOINT + ".sig", validSignature);
        String contentUrl = ENDPOINT.substring(0, ENDPOINT.lastIndexOf('/') + 1) + "versions/101/payload/Content/Paks/r101_SampleGame-Android.pak";
        Response completeContent = responses.get(contentUrl); Response truncated = new Response(bytes("bad")); truncated.declared = completeContent.declared; responses.put(contentUrl, truncated);
        ReleasePlayer.checkForUpdates(); awaitCheck();
        check(store().state().getJSONObject("active").getLong("releaseId") == 100 && libraryLoads == beforeLoad + 1, "Failed content transfer preserves complete running native/content pair");
        File root = (File) field("root"), incoming = new File(root, "incoming/r101");
        check(new File(incoming, "Content/Paks/r101_SampleGame-Android.pak.part").isFile() && !new File(root, "versions/101").exists(), "Interrupted transfer retains its actual partial download without a selectable immutable version");
        responses.put(contentUrl, completeContent); ReleasePlayer.checkForUpdates(); awaitCheck();
        JSONObject readyStatus = new JSONObject(ReleasePlayer.statusJson());
        check("ReadyToRestart".equals(readyStatus.getString("state")) && !readyStatus.getBoolean("checking")
                && readyStatus.getBoolean("restartRequired") && !readyStatus.getBoolean("startupPending")
                && readyStatus.getLong("readyReleaseId") == 101 && readyStatus.getLong("downloadedBytes") == readyStatus.getLong("totalBytes"), "Successful background stage publishes complete readiness, byte counts and finally checking=false");
        check(store().state().getJSONObject("active").getLong("releaseId") == 100 && new JSONObject(ReleasePlayer.selectionJson()).getLong("releaseId") == 100, "Downloading never activates the current process");
        check(!incoming.exists() && new File(root, "ready.json").isFile()
                && Arrays.equals(Files.readAllBytes(new File(root, "versions/101/libUnreal.so").toPath()), elf(101))
                && Arrays.equals(Files.readAllBytes(new File(root, "versions/101/Content/Paks/r101_SampleGame-Android.pak").toPath()), bytes("paired-pak-101")), "Successful stage and ready commit discard only the redundant download; the full immutable pair remains intact");
        check(new File(selectedSaves, "Saved/SaveGames/ColaLabQuickSave.sav").isFile() && new File(selected.getString("ackPath")).isFile(), "Download cleanup preserves the active save generation and boot health record");
        Files.write(new File(root, "versions/101/Content/Paks/r101_SampleGame-Android.pak").toPath(), bytes("corrupt-after-download"));
        reset(); healthy.getIntent().putExtra("cmdline", ""); prepareLoad(healthy);
        check(new JSONObject(ReleasePlayer.selectionJson()).getLong("releaseId") == 100 && store().state().getLong("highestReleaseId") == 101
                && store().state().getJSONArray("blocked").getLong(0) == 101, "Pre-load corruption blocks staged release and retains verified old native/content/save set");
        check(libraryLoads == beforeLoad + 2, "A rejected staged candidate invokes only the old verified library loader once");
        serve(base); confirm();

        JSONObject next = manifest(102); serve(next);
        android.util.AtomicFile.silentFailFinishName = "ready.json"; ReleasePlayer.checkForUpdates(); awaitCheck();
        check("UpdateFailed".equals(new JSONObject(ReleasePlayer.statusJson()).getString("state"))
                && store().state().getJSONObject("active").getLong("releaseId") == 100, "Silent ready-marker commit failure cannot activate a staged native/content pair");
        check(Arrays.equals(Files.readAllBytes(new File(root, "incoming/r102/libUnreal.so").toPath()), elf(102))
                && new File(root, "incoming/r102/Content/Paks/r102_SampleGame-Android.pak").isFile(), "Failed ready readback retains the full downloaded pair for a real retry");
        JSONObject preservedMarker = ReleaseSet.parse(Files.readAllBytes(new File(root, "ready.json").toPath()), 65536);
        check(preservedMarker.getLong("releaseId") == 101, "Failed ready commit preserves the previous marker for recovery");
        ReleasePlayer.checkForUpdates(); awaitCheck();
        check(!new File(root, "incoming/r102").exists() && "ReadyToRestart".equals(new JSONObject(ReleasePlayer.statusJson()).getString("state")), "Retry commits readiness then removes its own complete incoming tree");
        reset(); healthy.getIntent().putExtra("cmdline", ""); prepareLoad(healthy);
        JSONObject newer = new JSONObject(ReleasePlayer.selectionJson()); check(newer.getLong("releaseId") == 102, "Next cold process activates an actually different native/content pair");
        File newSave = new File(newer.getString("userRoot"), "Saved/SaveGames/ColaLabQuickSave.sav"); Files.write(newSave.toPath(), bytes("candidate-save-migration"));
        check(!newer.getString("userRoot").equals(selected.getString("userRoot")), "Activation forks a separate save generation");
        check(new String(Files.readAllBytes(legacy.toPath()), StandardCharsets.UTF_8).equals("historical-save-bytes"), "Candidate writes never change historical saves");
        reset(); serve(base); healthy.getIntent().putExtra("cmdline", ""); prepareLoad(healthy);
        JSONObject fallback = new JSONObject(ReleasePlayer.selectionJson());
        check(fallback.getLong("releaseId") == 100 && fallback.getString("userRoot").equals(selected.getString("userRoot")), "Unconfirmed native process death restores the entire prior payload and save generation");
        check(new String(Files.readAllBytes(newSave.toPath()), StandardCharsets.UTF_8).equals("candidate-save-migration"), "Failed candidate save generation remains available for recovery");
        check(store().state().getLong("highestReleaseId") == 102 && store().state().getJSONArray("blocked").length() == 2, "Process-death recovery retains anti-downgrade history");
        confirm();

        JSONObject lockedTarget = manifest(103); serve(lockedTarget);
        File lockedIncoming = new File(root, "incoming/r103"), heldNative = new File(lockedIncoming, "libUnreal.so");
        Files.createDirectories(lockedIncoming.toPath()); Files.write(heldNative.toPath(), elf(103));
        // Windows denies deletion of a java.io input handle without DELETE sharing.
        // Reads, hashing and Store.stage copying remain real and are still permitted.
        try (FileInputStream held = new FileInputStream(heldNative)) {
            ReleasePlayer.checkForUpdates(); awaitCheck();
            check(held.read() == 0x7f && heldNative.isFile(), "An actual open Windows file handle prevents incoming unlink after successful staging");
            check("ReadyToRestart".equals(new JSONObject(ReleasePlayer.statusJson()).getString("state"))
                    && new JSONObject(ReleasePlayer.statusJson()).getBoolean("restartRequired")
                    && ReleaseSet.parse(Files.readAllBytes(new File(root, "ready.json").toPath()), 65536).getLong("releaseId") == 103,
                    "Actual cleanup IO failure preserves the durable ready marker and restart notification");
        }
        byte[] durableState = Files.readAllBytes(new File(root, "state.json").toPath()), immutableNative = Files.readAllBytes(new File(root, "versions/103/libUnreal.so").toPath());
        check(!ReleasePlayer.discardStagedIncoming(root, 103) && !ReleasePlayer.discardStagedIncoming(new File(root, "versions/103"), 103)
                && !ReleasePlayer.discardStagedIncoming(lockedIncoming, 104), "Cleanup rejects the store root, an immutable version, and a mismatched incoming release");
        check(Arrays.equals(Files.readAllBytes(new File(root, "state.json").toPath()), durableState)
                && Arrays.equals(Files.readAllBytes(new File(root, "versions/103/libUnreal.so").toPath()), immutableNative)
                && new File(selectedSaves, "Saved/SaveGames/ColaLabQuickSave.sav").isFile(), "Rejected scopes preserve actual state, immutable payload and all prior saves");
        check(ReleasePlayer.discardStagedIncoming(lockedIncoming, 103) && !lockedIncoming.exists(), "Deferred cache cleanup succeeds once the actual file handle is released");
        File alias = new File(root, "incoming/r104");
        try {
            Files.createSymbolicLink(alias.toPath(), new File(root, "versions/103").toPath());
            check(!ReleasePlayer.discardStagedIncoming(alias, 104)
                    && Arrays.equals(Files.readAllBytes(new File(root, "versions/103/libUnreal.so").toPath()), immutableNative), "Incoming symlink cannot delete an immutable payload outside its exact directory");
            Files.delete(alias.toPath());
        } catch (UnsupportedOperationException | java.io.IOException unavailable) {
            System.out.println("ReleasePlayerHostTest: host symlink case unavailable; ordinary scope and actual unlink-failure cases still ran");
        }

        Response redirect = new Response(new byte[]{1}); redirect.status = 302; responses.put(ENDPOINT, redirect);
        rejects(() -> new ReleaseTransport(ENDPOINT).metadata(false), "Reject TLS redirect without following Location");
        Response encoded = new Response(new byte[]{1}); encoded.encoding = "gzip"; responses.put(ENDPOINT, encoded);
        rejects(() -> new ReleaseTransport(ENDPOINT).metadata(false), "Reject transformed payload encoding");
        Response oversized = new Response(new byte[]{1}); oversized.declared = ReleaseSet.MAX_MANIFEST + 1L; responses.put(ENDPOINT, oversized);
        rejects(() -> new ReleaseTransport(ENDPOINT).metadata(false), "Bound manifest HTTP content length before reading");

        reset(); TestActivity broken = new TestActivity("broken-base", bootstrap, base, true); int loadsBeforeBroken = libraryLoads;
        rejects(() -> ReleasePlayer.prepareForLaunch(broken), "APK content must match pinned full manifest before any native load");
        check(libraryLoads == loadsBeforeBroken, "Bad installed content never invokes System.load seam");
        rejects(() -> ReleasePlayer.prepareForLaunch(broken), "Preparation failure cannot silently select a new pair in the same process");

        reset(); TestActivity ambiguous = new TestActivity("ambiguous-saves", bootstrap, base, false);
        for (File parent : new File[]{ambiguous.getFilesDir(), ambiguous.getExternalFilesDir(null)}) {
            File old = new File(parent, "UnrealGame/SampleGame/SampleGame/Saved/SaveGames/ColaLabQuickSave.sav"); old.getParentFile().mkdirs(); Files.write(old.toPath(), bytes("unique-old-save"));
        }
        rejects(() -> ReleasePlayer.prepareForLaunch(ambiguous), "Multiple historical save roots require explicit migration instead of guessing");

        reset(); TestActivity staleExtras = new TestActivity("stale-early-extras", bootstrap, base, false);
        staleExtras.getIntent().putExtra("cmdline", "-SampleGameSkipBoot"); ReleasePlayer.prepareForLaunch(staleExtras);
        Activity oldGameActivity = new Activity(); oldGameActivity.getIntent().putExtra("cmdline", "-SampleGameSkipBoot");
        int beforeStaleExtras = libraryLoads;
        rejects(() -> ReleasePlayer.loadUnreal(oldGameActivity, ReleasePlayerHostTest.class.getClassLoader()), "An Intent containing only old QA flags cannot late-inject routing after GameActivity cached extras");
        check(libraryLoads == beforeStaleExtras && !store().state().isNull("boot"), "Stale early extras are rejected before any SO load and leave actual recovery pending");
        check("-SampleGameSkipBoot".equals(oldGameActivity.getIntent().getStringExtra("cmdline")), "Rejected startup does not rewrite the old Intent after its extras snapshot");

        reset(); TestActivity nativeFailure = new TestActivity("native-failure", bootstrap, base, false); ReleasePlayer.prepareForLaunch(nativeFailure);
        Activity failingGame = new Activity(); failingGame.getIntent().putExtra("cmdline", ReleasePlayer.launchArguments());
        ReleasePlayer.libraryLoader = (loader, library) -> { ++libraryLoads; throw new UnsatisfiedLinkError("Deliberate host-only native failure"); };
        boolean linked = false; try { ReleasePlayer.loadUnreal(failingGame, ReleasePlayerHostTest.class.getClassLoader()); } catch (UnsatisfiedLinkError expected) { linked = true; }
        check(linked, "A native constructor/load failure propagates instead of loading the APK SO"); int afterFailure = libraryLoads;
        rejects(() -> ReleasePlayer.loadUnreal(failingGame, ReleasePlayerHostTest.class.getClassLoader()), "No second native load after a failed first load");
        check(libraryLoads == afterFailure && !store().state().isNull("boot"), "Failed native load leaves pending recovery and no same-process fallback");
        reset();
        System.out.println("SAMPLEGAME_RELEASE_PLAYER_HOST_OK checks=" + checks + " libraryLoader=host-double TLS=host-double deviceRuntimeValidated=false");
    }
}
