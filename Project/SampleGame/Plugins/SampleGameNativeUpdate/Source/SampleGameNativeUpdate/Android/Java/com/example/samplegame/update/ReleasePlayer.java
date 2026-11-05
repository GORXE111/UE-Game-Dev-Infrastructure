package com.example.samplegame.update;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.util.AtomicFile;
import android.util.Base64;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/** Development APK release-set shell. Native code, full PAK set and saves move together. */
public final class ReleasePlayer {
    private static final String TAG = "SampleGameReleasePlayer";
    private static ReleaseSet.Store store;
    private static JSONObject config, selected, ticket;
    private static ReleaseSet.Verifier verifier;
    private static File root;
    private static boolean preparationAttempted, loadAttempted, confirmed;
    private static volatile boolean checking;
    private static volatile boolean prepared;
    private static volatile boolean libraryLoaded;
    private static String qaArguments = "";
    private static File ticketFile;
    private static long readyRelease, downloadedBytes, totalBytes;
    private static String state = "NotInitialized", message = "";
    private static volatile String statusSnapshot = "{\"state\":\"NotInitialized\",\"restartRequired\":false,\"startupPending\":false}";

    interface LibraryLoader { void load(ClassLoader loader, File library) throws Exception; }
    // A package-private seam permits policy/transport tests without claiming an actual SO load.
    static LibraryLoader libraryLoader = (loader, library) -> {
        NativeUpdate.protectLibrary(library);
        NativeUpdate.PathChange.install(loader, library);
        System.load(library.getCanonicalPath());
    };
    static { publishStatus(); }

    private ReleasePlayer() {}
    private static void require(boolean value, String detail) throws Exception { ReleaseTransport.require(value, detail); }
    private static boolean version(String value) {
        return value.length() <= 96 && value.matches("(?:0|[1-9][0-9]{0,2})\\.(?:0|[1-9][0-9]{0,2})\\.(?:0|[1-9][0-9]{0,2})(?:\\+[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*)?");
    }

    private static Set<String> names(JSONObject object) {
        Set<String> result = new HashSet<>(); Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }
    private static void keys(JSONObject object, String... expected) throws Exception {
        require(names(object).equals(new HashSet<>(Arrays.asList(expected))), "Unexpected player metadata fields");
    }

    /** Canonical ASCII JSON for bootstrap URLs/certificates; release manifests use ReleaseSet.parse. */
    static String canonical(Object value) throws Exception {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value; List<String> fields = new ArrayList<>(names(object)); Collections.sort(fields);
            StringBuilder output = new StringBuilder("{");
            for (String name : fields) {
                if (output.length() > 1) output.append(',');
                output.append(canonical(name)).append(':').append(canonical(object.get(name)));
            }
            return output.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value; StringBuilder output = new StringBuilder("[");
            for (int index = 0; index < array.length(); ++index) {
                if (index > 0) output.append(','); output.append(canonical(array.get(index)));
            }
            return output.append(']').toString();
        }
        if (value instanceof String) {
            String text = (String) value;
            require(text.matches("[\\x20-\\x7e]*"), "Non-ASCII player metadata string");
            // JSONObject.quote may escape '/', while the producer uses ordinary JSON slash bytes.
            return JSONObject.quote(text).replace("\\/", "/");
        }
        if (value instanceof Boolean) return value.toString();
        return Long.toString(ReleaseSet.number(value, 0, 9007199254740991L));
    }

    private static byte[] read(InputStream input, int maximum) throws Exception {
        try (InputStream source = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int count;
            while ((count = source.read(buffer)) != -1) {
                require(output.size() <= maximum - count, "Player metadata exceeds bound"); output.write(buffer, 0, count);
            }
            require(output.size() > 0, "Empty player metadata"); return output.toByteArray();
        }
    }
    private static byte[] raw(JSONObject value) throws Exception { return canonical(value).getBytes(StandardCharsets.UTF_8); }

    static JSONObject configuration(byte[] raw) throws Exception {
        require(raw.length > 0 && raw.length <= ReleaseSet.MAX_MANIFEST, "Invalid player bootstrap size");
        String source = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString();
        JSONObject value = new JSONObject(source);
        require(canonical(value).equals(source), "Noncanonical or ambiguous player bootstrap");
        keys(value, "format", "trust", "packageName", "manifestUrl", "allowOffline", "signatureAlgorithm", "certificateBase64", "certificateSha256", "baseArchiveEntries");
        ReleaseSet.number(value.get("format"), 1, 1);
        require(value.get("allowOffline") instanceof Boolean, "Expected offline policy boolean");
        require(value.getString("packageName").matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"), "Invalid package name");
        new ReleaseTransport(value.getString("manifestUrl"));
        require(value.getString("certificateBase64").length() <= 8192, "Trust certificate exceeds bound");
        byte[] certificate = Base64.decode(value.getString("certificateBase64"), Base64.NO_WRAP);
        require(certificate.length > 0 && certificate.length <= 4096 && ReleaseTransport.hash(certificate).equals(value.getString("certificateSha256")), "Pinned release certificate differs");
        PublicKey key = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate)).getPublicKey();
        ReleaseSet.certificateVerifier(key, value.getString("signatureAlgorithm"));
        JSONObject trust = value.getJSONObject("trust");
        keys(trust, "projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId", "loaderVersion", "baseManifestSha256");
        require("Android_ARM64".equals(trust.getString("platform")), "Android release platform required");
        ReleaseSet.number(trust.get("loaderVersion"), 1, 1);
        require(trust.getString("baseManifestSha256").matches("[a-f0-9]{64}"), "Missing pinned base manifest hash");
        ReleaseSet.parse(ReleaseSet.canonical(trust).getBytes(StandardCharsets.UTF_8), ReleaseSet.MAX_MANIFEST);
        JSONArray entries = value.getJSONArray("baseArchiveEntries");
        require(entries.length() > 1 && entries.length() <= 8192, "Incomplete base archive mapping");
        Set<String> paths = new HashSet<>(), locators = new HashSet<>();
        for (int index = 0; index < entries.length(); ++index) {
            JSONObject entry = entries.getJSONObject(index); keys(entry, "path", "apkPath", "obbPath");
            String path = ReleaseSet.relative(entry.getString("path")), apk = ReleaseSet.relative(entry.getString("apkPath")), obb = entry.getString("obbPath");
            require(paths.add(path.toLowerCase(java.util.Locale.ROOT)) && locators.add(apk + "!" + obb), "Duplicate base archive mapping");
            if ("libUnreal.so".equals(path)) require("lib/arm64-v8a/libUnreal.so".equals(apk) && obb.isEmpty(), "Unexpected base native source");
            else {
                require("assets/main.obb.png".equals(apk) && !obb.isEmpty(), "Unexpected base content archive");
                ReleaseSet.relative(obb);
            }
        }
        return value;
    }

    static void manifestPolicy(JSONObject manifest) throws Exception {
        JSONArray files = manifest.getJSONArray("files");
        String prefix = "r" + manifest.getLong("releaseId") + "_";
        for (int index = 0; index < files.length(); ++index) {
            JSONObject record = files.getJSONObject(index);
            if ("content".equals(record.getString("role"))) {
                String path = record.getString("path");
                require(path.startsWith("Content/Paks/" + prefix) && path.indexOf('/', "Content/Paks/".length()) < 0,
                        "Android PAK must have a unique release-prefixed filename");
                require(path.length() > "Content/Paks/".length() + prefix.length() + 4, "Empty Android PAK basename");
            }
        }
    }

    static void extractBase(File apk, File destination, JSONObject bootstrap, JSONObject manifest) throws Exception {
        ReleaseTransport.mkdir(destination);
        JSONArray files = manifest.getJSONArray("files"), mappings = bootstrap.getJSONArray("baseArchiveEntries");
        Map<String, JSONObject> records = new HashMap<>(), mapping = new HashMap<>();
        for (int index = 0; index < files.length(); ++index) records.put(files.getJSONObject(index).getString("path"), files.getJSONObject(index));
        for (int index = 0; index < mappings.length(); ++index) mapping.put(mappings.getJSONObject(index).getString("path"), mappings.getJSONObject(index));
        require(records.keySet().equals(mapping.keySet()), "APK mapping and pinned payload differ");
        Map<String, String> nested = new HashMap<>(); Set<String> found = new HashSet<>();
        try (ZipFile archive = new ZipFile(apk)) {
            Set<String> allNames = new HashSet<>(); java.util.Enumeration<? extends ZipEntry> entries = archive.entries();
            while (entries.hasMoreElements()) require(allNames.add(entries.nextElement().getName()), "Ambiguous duplicate APK entry");
            for (String path : records.keySet()) {
                JSONObject item = mapping.get(path);
                if (!item.getString("obbPath").isEmpty()) { nested.put(item.getString("obbPath"), path); continue; }
                ZipEntry entry = archive.getEntry(item.getString("apkPath"));
                require(entry != null && !entry.isDirectory() && entry.getSize() == records.get(path).getLong("size"), "Pinned APK native entry missing or truncated");
                File output = ReleaseTransport.child(destination, path);
                if (!ReleaseTransport.matches(output, records.get(path))) {
                    require(!output.exists() || output.delete(), "Cannot replace incomplete base extraction");
                    try (InputStream input = archive.getInputStream(entry)) { ReleaseTransport.copyVerified(input, output, records.get(path)); }
                }
                found.add(path);
            }
            ZipEntry container = archive.getEntry("assets/main.obb.png");
            require(container != null && !container.isDirectory(), "Embedded complete content archive missing");
            Set<String> nestedNames = new HashSet<>();
            try (ZipInputStream input = new ZipInputStream(archive.getInputStream(container))) {
                ZipEntry entry;
                while ((entry = input.getNextEntry()) != null) {
                    require(nestedNames.add(entry.getName()), "Ambiguous duplicate OBB entry");
                    String path = nested.get(entry.getName());
                    if (path != null) {
                        JSONObject record = records.get(path);
                        require(!entry.isDirectory() && (entry.getSize() < 0 || entry.getSize() == record.getLong("size")), "Pinned OBB entry differs");
                        File output = ReleaseTransport.child(destination, path);
                        if (!ReleaseTransport.matches(output, record)) {
                            require(!output.exists() || output.delete(), "Cannot replace incomplete base content");
                            // The caller owns the nested stream; copyVerified does not close it.
                            ReleaseTransport.copyVerified(input, output, record);
                        }
                        found.add(path);
                    }
                    input.closeEntry();
                }
            }
        }
        require(found.equals(records.keySet()), "Installed APK does not contain the entire pinned base set");
    }

    private static void atomic(File destination, byte[] bytes) throws Exception {
        ReleaseTransport.mkdir(destination.getParentFile());
        AtomicFile file = new AtomicFile(destination); FileOutputStream output = null;
        try {
            output = file.startWrite(); output.write(bytes); output.getFD().sync(); file.finishWrite(output);
        } catch (Exception error) { if (output != null) file.failWrite(output); throw error; }
        require(Arrays.equals(bytes, read(file.openRead(), ReleaseSet.MAX_MANIFEST)), "Player metadata atomic commit failed readback");
    }

    private static void setState(String value, String detail) {
        state = value; message = detail; publishStatus(); Log.i(TAG, value + ": " + detail);
    }

    private static void initialize(Activity activity) throws Exception {
        config = configuration(read(activity.getAssets().open("release-player.json"), ReleaseSet.MAX_MANIFEST));
        publishStatus();
        require(activity.getPackageName().equals(config.getString("packageName")), "Bootstrap belongs to another APK package");
        byte[] certificate = Base64.decode(config.getString("certificateBase64"), Base64.NO_WRAP);
        verifier = ReleaseSet.certificateVerifier(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate)).getPublicKey(), config.getString("signatureAlgorithm"));
        JSONObject trust = config.getJSONObject("trust");
        File privateRoot = activity.getDir("samplegame-release-sets", Activity.MODE_PRIVATE).getCanonicalFile();
        root = ReleaseTransport.child(privateRoot, "b" + trust.getLong("baseReleaseId") + "-" + trust.getString("baseManifestSha256").substring(0, 16));
        ReleaseTransport.mkdir(root);
        store = new ReleaseSet.Store(root, trust, verifier);
        File stateFile = ReleaseTransport.child(root, "state.json"), backup = ReleaseTransport.child(root, "state.json.bak");
        if (!stateFile.exists() && !backup.exists()) {
            byte[] baseRaw = read(activity.getAssets().open("release-base-manifest.json"), ReleaseSet.MAX_MANIFEST);
            require(ReleaseTransport.hash(baseRaw).equals(trust.getString("baseManifestSha256")), "Installed base manifest pin differs");
            JSONObject base = ReleaseSet.manifest(baseRaw, trust); manifestPolicy(base);
            File extraction = ReleaseTransport.child(root, "base-extraction");
            extractBase(new File(activity.getApplicationInfo().sourceDir), extraction, config, base);
            File legacy = previousBaseSnapshot(privateRoot, root, base);
            if (legacy == null) legacy = legacySnapshot(activity, root);
            store.initialize(extraction, baseRaw, legacy);
            removeExtraction(extraction);
            if (legacy != null) removeExtraction(legacy);
        }
        JSONObject recovered = store.recover();
        File ready = ReleaseTransport.child(root, "ready.json");
        if (ready.exists() || new File(ready.getPath() + ".bak").exists()) {
            JSONObject marker = ReleaseSet.parse(read(new AtomicFile(ready).openRead(), 65536), 65536);
            keys(marker, "format", "releaseId", "manifestSha256"); ReleaseSet.number(marker.get("format"), 1, 1);
            long candidate = ReleaseSet.number(marker.get("releaseId"), trust.getLong("baseReleaseId") + 1, 9007199254740991L);
            require(marker.getString("manifestSha256").matches("[a-f0-9]{64}"), "Invalid ready manifest hash");
            if (candidate > recovered.getLong("highestReleaseId")) {
                try {
                    File cached = ReleaseTransport.child(root, "versions/" + candidate + "/manifest.json");
                    require(ReleaseTransport.hash(cached).equals(marker.getString("manifestSha256")), "Ready version identity differs");
                    store.activate(candidate);
                }
                catch (Exception error) {
                    store.rejectStaged(candidate);
                    setState("CandidateRejected", "Damaged staged set blocked before any native library load");
                }
            }
        }
        selected = store.boot(); manifestPolicy(selected.getJSONObject("manifest"));
        JSONObject reference = selected.getJSONObject("reference"), manifest = selected.getJSONObject("manifest");
        File boot = ReleaseTransport.child(root, "boots/" + selected.getString("attemptId")); ReleaseTransport.mkdir(boot);
        ticket = new JSONObject().put("format", 1).put("attemptId", selected.getString("attemptId"))
                .put("releaseId", reference.getLong("releaseId")).put("manifestSha256", reference.getString("manifestSha256"))
                .put("buildId", manifest.getString("buildId")).put("saveSchema", manifest.getJSONObject("save").getLong("schema"))
                .put("payloadRoot", selected.getString("payloadRoot")).put("userRoot", selected.getString("savesRoot"))
                .put("ackPath", new File(boot, "health.json").getCanonicalPath());
        atomic(new File(boot, "ticket.json"), raw(ticket));
        ticketFile = new File(boot, "ticket.json");
        // The exported bootstrap Activity accepts diagnostic launch options only in debuggable builds.
        qaArguments = (activity.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0
                ? activity.getIntent().getStringExtra("cmdline") : null;
        arguments(ticket, manifest, ticketFile, qaArguments); // Validate before another Activity starts.
        File library = new File(selected.getString("payloadRoot"), "libUnreal.so");
        JSONObject nativeRecord = nativeRecord(manifest);
        NativeUpdatePolicy.verifyFile(library, nativeRecord.getLong("size"), nativeRecord.getString("sha256"));
        setState("BootPending", "Verified complete native/content/save generation selected");
    }

    private static void legacyFiles(File base, File directory, Map<String, File> result) throws Exception {
        require(base.getAbsoluteFile().equals(base.getCanonicalFile()) && directory.getAbsoluteFile().equals(directory.getCanonicalFile()), "Aliased legacy save source");
        File[] files = directory.listFiles(); require(files != null, "Cannot enumerate legacy save source");
        for (File file : files) {
            require(file.getAbsoluteFile().equals(file.getCanonicalFile()), "Aliased legacy save file");
            if (file.isDirectory()) legacyFiles(base, file, result);
            else {
                require(file.isFile(), "Legacy save source is not a regular file");
                String name = base.toURI().relativize(file.toURI()).getPath(); ReleaseSet.relative(name);
                require(result.size() < 4096 && result.put(name, file) == null, "Legacy save inventory exceeds bound");
            }
        }
    }

    private static File previousBaseSnapshot(File parent, File destination, JSONObject base) throws Exception {
        final long oldId = 430L;
        final String pinned = "0000000000000000000000000000000000000000000000000000000000000000";
        if (base.getLong("baseReleaseId") <= oldId) return null;
        File old = ReleaseTransport.child(parent, "b" + oldId + "-" + pinned.substring(0, 16));
        if (!new File(old, "state.json").exists() && !new File(old, "state.json.bak").exists()) return null;
        byte[] raw = read(new FileInputStream(ReleaseTransport.child(old, "versions/" + oldId + "/manifest.json")), ReleaseSet.MAX_MANIFEST);
        require(ReleaseTransport.hash(raw).equals(pinned), "Prior base is not the official pinned baseline");
        JSONObject value = ReleaseSet.parse(raw, ReleaseSet.MAX_MANIFEST), trust = new JSONObject();
        for (String name : new String[]{"projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId"}) trust.put(name, value.get(name));
        trust.put("loaderVersion", 1).put("baseManifestSha256", pinned);
        require("SampleGame".equals(trust.getString("projectId")) && "Android_ARM64".equals(trust.getString("platform")), "Prior base belongs to another product");
        return releaseSnapshot(old, destination, trust, base.getJSONObject("save").getJSONArray("readable"), verifier);
    }

    static File releaseSnapshot(File oldRoot, File destination, JSONObject oldTrust, JSONArray readable, ReleaseSet.Verifier verify) throws Exception {
        require(!oldRoot.getCanonicalFile().equals(destination.getCanonicalFile()), "Save import source is the new store");
        try (ReleaseSet.Store old = new ReleaseSet.Store(oldRoot, oldTrust, verify)) {
            JSONObject selected = old.confirmedSaveSource(readable);
            File saved = ReleaseTransport.child(new File(selected.getString("savesRoot")), "Saved");
            Map<String, File> inventory = new HashMap<>();
            if (saved.exists()) {
                require(saved.isDirectory(), "Prior Saved tree is not a directory");
                for (String name : new String[]{"SaveGames", "Config"}) {
                    File tree = ReleaseTransport.child(saved, name);
                    if (tree.exists()) { require(tree.isDirectory(), "Prior user tree is not a directory"); legacyFiles(saved, tree, inventory); }
                }
            }
            File snapshot = copyLegacyInventory(destination, inventory);
            atomic(ReleaseTransport.child(destination, "save-import.json"), raw(new JSONObject().put("format", 1)
                    .put("sourceBaseReleaseId", oldTrust.getLong("baseReleaseId")).put("selection", selected)));
            return snapshot;
        }
    }

    /** Import only the two authored user-data trees from the known pre-V106 Development layout. */
    static File legacySnapshot(Activity activity, File privateRoot) throws Exception {
        List<Map<String, File>> candidates = new ArrayList<>(); Set<String> roots = new HashSet<>();
        for (File parent : new File[]{activity.getFilesDir(), activity.getExternalFilesDir(null)}) {
            if (parent == null) continue;
            File old = new File(parent.getCanonicalFile(), "UnrealGame/SampleGame/SampleGame/Saved");
            require(old.getAbsoluteFile().equals(old.getCanonicalFile()), "Aliased legacy user root");
            if (!old.isDirectory() || !roots.add(old.getCanonicalPath())) continue;
            Map<String, File> inventory = new HashMap<>();
            for (String name : new String[]{"SaveGames", "Config"}) {
                File tree = new File(old, name);
                if (tree.exists()) { require(tree.isDirectory(), "Legacy user tree is not a directory"); legacyFiles(old, tree, inventory); }
            }
            if (!inventory.isEmpty()) candidates.add(inventory);
        }
        require(candidates.size() <= 1, "Multiple historical save locations contain data; explicit migration is required");
        if (candidates.isEmpty()) return null;
        return copyLegacyInventory(privateRoot, candidates.get(0));
    }

    private static File copyLegacyInventory(File privateRoot, Map<String, File> inventory) throws Exception {
        long bytes = 0; Set<String> names = new HashSet<>();
        for (String name : inventory.keySet()) {
            require(names.add(name.toLowerCase(java.util.Locale.ROOT)), "Ambiguous legacy save filename"); bytes += inventory.get(name).length();
        }
        require(bytes <= 256L * 1024 * 1024 && privateRoot.getUsableSpace() >= 2 * bytes + 32L * 1024 * 1024, "Legacy save snapshot exceeds budget");
        File snapshot = ReleaseTransport.child(privateRoot, "legacy-import-" + UUID.randomUUID().toString().replace("-", "")); ReleaseTransport.mkdir(snapshot);
        for (String name : inventory.keySet()) {
            File source = inventory.get(name), destination = ReleaseTransport.child(snapshot, "Saved/" + name);
            String before = ReleaseTransport.hash(source); long length = source.length(); ReleaseTransport.mkdir(destination.getParentFile());
            try (FileInputStream input = new FileInputStream(source); FileOutputStream output = new FileOutputStream(destination)) {
                byte[] buffer = new byte[262144]; int count; long copied = 0;
                while ((count = input.read(buffer)) != -1) { require(count <= length - copied, "Legacy save changed during snapshot"); copied += count; output.write(buffer, 0, count); }
                require(copied == length, "Legacy save was truncated during snapshot"); output.getFD().sync();
            }
            require(ReleaseTransport.hash(source).equals(before) && ReleaseTransport.hash(destination).equals(before), "Legacy save changed during cold snapshot");
        }
        return snapshot;
    }

    private static void removeExtraction(File directory) throws Exception {
        require(directory.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator) && directory.getAbsoluteFile().equals(directory.getCanonicalFile()), "Extraction cleanup escaped private root");
        File[] children = directory.listFiles(); require(children != null, "Cannot enumerate extraction directory");
        for (File child : children) {
            require(child.getAbsoluteFile().equals(child.getCanonicalFile()), "Aliased extracted file");
            if (child.isDirectory()) removeExtraction(child);
            else require(child.isFile() && child.delete(), "Cannot remove copied extraction file");
        }
        require(directory.delete(), "Cannot remove extraction directory");
    }

    /** Called only after Store.stage verifies both exact inventories and ready commits. */
    static boolean discardStagedIncoming(File directory, long release) {
        try {
            File expected = ReleaseTransport.child(root, "incoming/r" + release);
            require(directory.getAbsoluteFile().equals(expected) && directory.getAbsoluteFile().equals(directory.getCanonicalFile()), "Incoming cleanup escaped staged download");
            removeExtraction(directory);
            return true;
        } catch (Exception error) {
            Log.w(TAG, "Staged update remains ready; incoming cache cleanup deferred", error);
            return false;
        }
    }

    static String arguments(JSONObject selection, JSONObject manifest, File ticketPath, String original) throws Exception {
        List<String> pakNames = new ArrayList<>(); JSONArray files = manifest.getJSONArray("files");
        for (int index = 0; index < files.length(); ++index) {
            JSONObject file = files.getJSONObject(index);
            if ("content".equals(file.getString("role"))) {
                String name = new File(file.getString("path")).getName();
                pakNames.add(name.substring(0, name.length() - 4));
            }
        }
        Collections.sort(pakNames);
        String fixed = "-UserDir=\"" + selection.getString("userRoot") + "\" -pakdir=\""
                + selection.getString("payloadRoot") + "/Content/Paks\" -paklist=" + join(pakNames)
                + " -SampleGameReleaseTicket=\"" + ticketPath.getCanonicalPath() + "\"";
        if (original == null || original.trim().isEmpty()) return fixed;
        require(original.length() <= 2048, "QA arguments exceed bound");
        StringBuilder accepted = new StringBuilder(); Set<String> fields = new HashSet<>();
        for (String argument : original.trim().split("\\s+")) {
            require(argument.matches("-(SampleGameSkipBoot|SampleGameMenuProbe)")
                    || argument.matches("-SampleGameBootExitAfterMenu=(?:[0-9]{1,4})(?:\\.[0-9]{1,3})?")
                    || (argument.startsWith("-SampleGameExpectedContentVersion=") && version(argument.substring("-SampleGameExpectedContentVersion=".length()))), "Untrusted Android startup argument");
            require(fields.add(argument.split("=", 2)[0]), "Duplicate QA argument"); accepted.append(' ').append(argument);
        }
        return fixed + accepted;
    }

    private static String join(List<String> values) {
        StringBuilder result = new StringBuilder();
        for (String value : values) { if (result.length() > 0) result.append('+'); result.append(value); }
        return result.toString();
    }

    private static JSONObject nativeRecord(JSONObject manifest) throws Exception {
        JSONArray files = manifest.getJSONArray("files"); JSONObject result = null;
        for (int index = 0; index < files.length(); ++index) if ("native".equals(files.getJSONObject(index).getString("role"))) result = files.getJSONObject(index);
        require(result != null, "Selected native file missing"); return result;
    }

    /** Called on the bootstrap worker. No hashing, extraction or network runs on Android's UI thread. */
    public static synchronized void prepareForLaunch(Activity activity) throws Exception {
        if (prepared) return;
        require(!preparationAttempted && !loadAttempted, "A failed preparation requires a new Android process");
        preparationAttempted = true;
        try { initialize(activity); prepared = true; }
        catch (Exception error) { setState("PreparationFailed", error.getClass().getSimpleName() + ": " + error.getMessage()); throw error; }
    }

    /** UPL invokes this before any native library load or NativeActivity.onCreate. */
    public static synchronized void loadUnreal(Activity activity, ClassLoader loader) {
        if (libraryLoaded) return;
        if (loadAttempted) throw new IllegalStateException("A failed native load requires a new Android process");
        if (!prepared && !preparationAttempted && android.os.Build.VERSION.SDK_INT >= 26 && android.os.Build.VERSION.SDK_INT <= 27) {
            loadAttempted = true;
            ReleaseRecovery.restartLegacy(activity);
        }
        loadAttempted = true;
        try {
            require(prepared && selected != null && ticket != null, "Start the release bootstrap Activity before loading Unreal");
            require(launchArguments().equals(activity.getIntent().getStringExtra("cmdline")),
                    "Validated command line must reach GameActivity before its early extras snapshot");
            File library = new File(selected.getString("payloadRoot"), "libUnreal.so");
            libraryLoader.load(loader, library);
            libraryLoaded = true;
            publishStatus();
            Log.i(TAG, "SAMPLEGAME_RELEASE_LIBRARY_LOADED release=" + ticket.getLong("releaseId") + " native=" + selected.getJSONObject("manifest").getString("nativeSourceHash"));
        } catch (Exception error) {
            setState("StartupFailed", error.getClass().getSimpleName() + ": " + error.getMessage());
            throw new IllegalStateException("Release-set startup failed; restart or repair installation", error);
        } catch (LinkageError error) {
            setState("NativeLoadFailed", error.toString()); throw error;
        }
        // Never close the lease, restore another library path, or load the APK SO here.
    }

    public static synchronized String selectionJson() {
        try { return ticket == null ? "{}" : canonical(ticket); }
        catch (Exception error) { throw new IllegalStateException("Selection serialization failed", error); }
    }

    public static boolean isLibraryLoaded() { return libraryLoaded; }
    public static boolean isPrepared() { return prepared; }

    /** The outgoing Splash Intent must carry this before GameActivity snapshots its extras. */
    public static synchronized String launchArguments() {
        try {
            require(prepared && selected != null && ticket != null, "Release selection is not ready to launch");
            return arguments(ticket, selected.getJSONObject("manifest"), ticketFile, qaArguments);
        } catch (Exception error) { throw new IllegalStateException("Prepared launch arguments unavailable", error); }
    }

    /** Only real UE world/Lua/save/pak readiness may call this with the exact current process identity. */
    public static synchronized boolean acknowledge(String json) {
        try {
            require(libraryLoaded && !confirmed && ticket != null && json != null && json.length() <= 8192, "No unconfirmed loaded release");
            JSONObject ack = new JSONObject(json);
            keys(ack, "format", "attemptId", "releaseId", "manifestSha256", "buildId", "saveSchema", "pid", "userRoot", "luaVersion");
            ReleaseSet.number(ack.get("format"), 1, 1);
            for (String key : new String[]{"attemptId", "manifestSha256", "buildId", "userRoot"}) require(ack.getString(key).equals(ticket.getString(key)), "Health selection mismatch: " + key);
            require(ReleaseSet.number(ack.get("releaseId"), 1, 9007199254740991L) == ticket.getLong("releaseId")
                    && ReleaseSet.number(ack.get("saveSchema"), 0, 10000) == ticket.getLong("saveSchema")
                    && ReleaseSet.number(ack.get("pid"), 1, Integer.MAX_VALUE) == Process.myPid()
                    && version(ack.getString("luaVersion")), "Health runtime identity differs");
            // Preserve an actual health record before the single durable transaction confirms.
            atomic(new File(ticket.getString("ackPath")), raw(ack));
            store.confirm(ticket.getString("attemptId"), ticket.getLong("releaseId"), ticket.getString("manifestSha256"), ticket.getLong("saveSchema"));
            confirmed = true; setState("Active", "Native, selected PAKs, Lua and save generation confirmed");
            checkForUpdates();
            return true;
        } catch (Exception error) { setState("ConfirmationFailed", error.getClass().getSimpleName() + ": " + error.getMessage()); return false; }
    }

    public static void checkForUpdates() {
        if (checking) return;
        synchronized (ReleasePlayer.class) {
            if (!libraryLoaded || !confirmed || checking || config == null) return;
            checking = true; downloadedBytes = 0; totalBytes = 0; setState("Checking", "Checking complete signed release set");
            Thread worker = new Thread(() -> {
                try { checkAndStage(); }
                catch (Exception error) {
                    synchronized (ReleasePlayer.class) { setState("UpdateFailed", error.getClass().getSimpleName() + ": " + error.getMessage()); }
                } finally { synchronized (ReleasePlayer.class) { checking = false; publishStatus(); } }
            }, "SampleGameReleaseDownload");
            worker.setDaemon(true); worker.start();
        }
    }

    private static void checkAndStage() throws Exception {
        ReleaseTransport transport = new ReleaseTransport(config.getString("manifestUrl"));
        byte[] raw = transport.metadata(false), signature = transport.metadata(true);
        verifier.verify(raw, signature);
        JSONObject candidate = ReleaseSet.manifest(raw, config.getJSONObject("trust")); manifestPolicy(candidate);
        long release = candidate.getLong("releaseId");
        synchronized (ReleasePlayer.class) {
            if (release <= store.state().getLong("highestReleaseId") || release <= readyRelease) { setState("UpToDate", "No newer acceptable complete release"); return; }
            JSONArray files = candidate.getJSONArray("files");
            for (int index = 0; index < files.length(); ++index) totalBytes += files.getJSONObject(index).getLong("size");
            setState("Downloading", "Downloading full paired native/content payload for next cold start");
        }
        File incoming = ReleaseTransport.child(root, "incoming/r" + release); ReleaseTransport.mkdir(incoming);
        transport.payload(candidate, incoming);
        JSONObject nativeRecord = null; JSONArray files = candidate.getJSONArray("files");
        for (int index = 0; index < files.length(); ++index) if ("native".equals(files.getJSONObject(index).getString("role"))) nativeRecord = files.getJSONObject(index);
        require(nativeRecord != null, "Signed native payload missing");
        NativeUpdatePolicy.verifyFile(new File(incoming, "libUnreal.so"), nativeRecord.getLong("size"), nativeRecord.getString("sha256"));
        synchronized (ReleasePlayer.class) {
            store.stage(incoming, raw, signature);
            atomic(ReleaseTransport.child(root, "ready.json"), raw(new JSONObject().put("format", 1).put("releaseId", release).put("manifestSha256", ReleaseTransport.hash(raw))));
            downloadedBytes = transport.downloadedBytes(); readyRelease = release;
            setState("ReadyToRestart", "Complete signed native/content set staged; restart to activate");
            discardStagedIncoming(incoming, release);
        }
    }

    /** Writers hold the transaction monitor; readers never wait for payload IO. */
    private static void publishStatus() {
        JSONObject result = new JSONObject();
        try {
            result.put("platform", "Android_ARM64").put("enabled", config != null).put("managedByReleaseSet", true)
                    .put("state", state).put("message", message).put("checking", checking)
                    .put("loadedReleaseId", ticket == null ? 0 : ticket.getLong("releaseId"))
                    .put("readyReleaseId", readyRelease).put("nativeSourceHash", selected == null ? "" : selected.getJSONObject("manifest").getString("nativeSourceHash"))
                    .put("libraryPath", selected == null ? "" : new File(selected.getString("payloadRoot"), "libUnreal.so").getPath())
                    .put("downloadedBytes", downloadedBytes).put("totalBytes", totalBytes)
                    .put("restartRequired", ticket != null && readyRelease > ticket.getLong("releaseId"))
                    .put("startupPending", libraryLoaded && !confirmed);
            statusSnapshot = result.toString();
        } catch (Exception error) { Log.w(TAG, "Release status serialization failed", error); }
    }

    public static String statusJson() { return statusSnapshot; }
}
