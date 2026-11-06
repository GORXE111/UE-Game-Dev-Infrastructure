package com.example.samplegame.update;

import android.util.AtomicFile;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** V1.0.6 native/content/save transaction shared with the desktop producer. */
public final class ReleaseSet {
    public static final int MAX_MANIFEST = 1024 * 1024;
    private static final long MAX_NUMBER = 9007199254740991L;
    private static final String[] BINDINGS = {"projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId"};
    private ReleaseSet() {}

    public interface Verifier { void verify(byte[] raw, byte[] signature) throws Exception; }

    private static void require(boolean ok, String message) throws IOException {
        if (!ok) throw new IOException(message);
    }

    private static boolean token(String value) { return value.matches("[A-Za-z0-9_.-]{1,128}"); }

    private static Set<String> fieldNames(JSONObject value) {
        Set<String> names = new HashSet<>();
        java.util.Iterator<String> iterator = value.keys();
        while (iterator.hasNext()) names.add(iterator.next());
        return names;
    }

    private static void keys(JSONObject value, String... names) throws Exception {
        require(fieldNames(value).equals(new HashSet<>(Arrays.asList(names))), "Unexpected release-set fields");
    }

    public static long number(Object raw, long minimum, long maximum) throws Exception {
        require(raw instanceof Integer || raw instanceof Long, "Expected integral JSON number");
        long value = ((Number) raw).longValue();
        require(value >= minimum && value <= maximum, "Release-set integer outside bounds");
        return value;
    }

    private static String text(JSONObject object, String key) throws Exception {
        Object value = object.get(key);
        require(value instanceof String, "Expected release-set string");
        return (String) value;
    }

    private static String sha(Object value) throws Exception {
        require(value instanceof String && ((String) value).matches("[a-f0-9]{64}"), "Invalid SHA256");
        return (String) value;
    }

    public static String canonical(Object value) throws Exception {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> names = new ArrayList<>(fieldNames(object));
            Collections.sort(names);
            StringBuilder result = new StringBuilder("{");
            for (String name : names) {
                if (result.length() > 1) result.append(',');
                result.append(canonical(name)).append(':').append(canonical(object.get(name)));
            }
            return result.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            StringBuilder result = new StringBuilder("[");
            for (int index = 0; index < array.length(); ++index) {
                if (index > 0) result.append(',');
                result.append(canonical(array.get(index)));
            }
            return result.append(']').toString();
        }
        if (value instanceof String) {
            String string = (String) value;
            // Protocol strings are ASCII identifiers and paths. Reject alternative
            // escape encodings so Android and the producer interpret identical bytes.
            require(string.matches("[A-Za-z0-9_./-]*"), "Noncanonical release-set string");
            return "\"" + string + "\"";
        }
        if (value instanceof Boolean) return value.toString();
        return Long.toString(number(value, 0, MAX_NUMBER));
    }

    public static JSONObject parse(byte[] raw, int maximum) throws Exception {
        require(raw.length > 0 && raw.length <= maximum, "Invalid release-set metadata size");
        String source = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString();
        JSONObject value = new JSONObject(source);
        require(canonical(value).equals(source), "Noncanonical or ambiguous release-set JSON");
        return value;
    }

    private static String hash(byte[] bytes) throws Exception {
        return NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String hash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[262144];
        try (FileInputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return NativeUpdatePolicy.hex(digest.digest());
    }

    public static Verifier certificateVerifier(PublicKey key, String algorithm) throws Exception {
        require(("SHA256withRSA".equals(algorithm) && "RSA".equals(key.getAlgorithm()))
                || ("SHA256withECDSA".equals(algorithm) && "EC".equals(key.getAlgorithm())), "Unsupported release-set signer");
        return (raw, signed) -> {
            require(raw.length > 0 && raw.length <= MAX_MANIFEST && signed.length > 0 && signed.length <= 8192, "Invalid signature input size");
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(raw);
            require(verifier.verify(signed), "Release-set signature rejected");
        };
    }

    public static String relative(String name) throws Exception {
        require(name.length() > 0 && name.length() <= 240 && !name.startsWith("/"), "Invalid release-set path");
        for (String part : name.split("/", -1)) {
            require(token(part) && !part.equals(".") && !part.equals("..") && !part.endsWith("."), "Unsafe path component");
            require(!part.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?"), "Device path forbidden");
        }
        return name;
    }

    private static File child(File root, String name) throws Exception {
        relative(name);
        require(root.isDirectory() && root.getAbsoluteFile().equals(root.getCanonicalFile()), "Aliased release root");
        File file = new File(root, name);
        require(file.getAbsoluteFile().equals(file.getCanonicalFile()) && file.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator), "Aliased release path");
        return file;
    }

    private static void mkdir(File path) throws Exception {
        require(path.isDirectory() || path.mkdirs(), "Cannot create release-set directory");
        require(path.getAbsoluteFile().equals(path.getCanonicalFile()), "Aliased directory");
    }

    private static byte[] read(File file, int maximum) throws Exception {
        require(file.isFile() && file.length() <= maximum, "Invalid metadata file");
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                require(output.size() <= maximum - count, "Metadata exceeds bound");
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static void writeNew(File file, byte[] raw) throws Exception {
        require(file.createNewFile(), "Release file already exists");
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(raw);
            output.getFD().sync();
        }
    }

    private static void copy(File source, File destination) throws Exception {
        require(source.isFile() && source.getAbsoluteFile().equals(source.getCanonicalFile()), "Invalid source file");
        mkdir(destination.getParentFile());
        require(destination.createNewFile(), "Copy target already exists");
        try (FileInputStream input = new FileInputStream(source); FileOutputStream output = new FileOutputStream(destination)) {
            byte[] buffer = new byte[262144];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            output.getFD().sync();
        }
    }

    public static void savePolicy(JSONObject value) throws Exception {
        keys(value, "schema", "readable", "migrations");
        long schema = number(value.get("schema"), 0, 10000);
        JSONArray readable = value.getJSONArray("readable"), migrations = value.getJSONArray("migrations");
        require(readable.length() > 0 && readable.length() <= 64 && migrations.length() <= 64, "Invalid save policy lengths");
        Set<Long> expected = new java.util.TreeSet<>();
        long last = -1;
        for (int index = 0; index < readable.length(); ++index) {
            long version = number(readable.get(index), 0, schema);
            require(version > last, "Readable save schemas are not ordered");
            last = version;
            for (long step = version; step < schema; ++step) {
                expected.add(step);
                require(expected.size() <= 64, "Save migration path too long");
            }
        }
        require(last == schema && migrations.length() == expected.size(), "Incomplete save migration path");
        Set<String> ids = new HashSet<>();
        int index = 0;
        for (long first : expected) {
            JSONObject migration = migrations.getJSONObject(index++);
            keys(migration, "from", "to", "id");
            require(number(migration.get("from"), 0, 10000) == first && number(migration.get("to"), 0, 10000) == first + 1,
                    "Noncontiguous save migration");
            String id = text(migration, "id");
            require(token(id) && ids.add(id), "Duplicate migration identity");
        }
    }

    public static String buildId(JSONObject value) throws Exception {
        JSONObject inputs = new JSONObject();
        for (String name : new String[]{"sourceCommit", "nativeSourceHash", "files", "save"}) inputs.put(name, value.get(name));
        return hash(canonical(inputs).getBytes(StandardCharsets.UTF_8));
    }

    public static JSONObject manifest(byte[] raw, JSONObject trust) throws Exception {
        JSONObject value = parse(raw, MAX_MANIFEST);
        keys(value, "format", "kind", "projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId",
                "releaseId", "minLoaderVersion", "sourceCommit", "nativeSourceHash", "buildId", "files", "save");
        require(number(value.get("format"), 1, 1) == 1 && text(value, "kind").equals("samplegame-release-set"), "Unsupported release set");
        for (String name : BINDINGS) require(canonical(value.get(name)).equals(canonical(trust.get(name))), "Shell binding differs: " + name);
        String project = text(value, "projectId");
        require((project.equals("SampleGame") || project.equals("ProfileSample"))
                && text(value, "platform").equals("Android_ARM64"), "Expected Android game release set");
        for (String name : new String[]{"projectId", "channel", "engineBuildId"}) require(token(text(value, name)), "Invalid identity token");
        sha(value.get("shellCompatibilityId"));
        number(value.get("baseReleaseId"), 1, MAX_NUMBER);
        number(value.get("releaseId"), number(value.get("baseReleaseId"), 1, MAX_NUMBER), MAX_NUMBER);
        number(value.get("minLoaderVersion"), 1, number(trust.get("loaderVersion"), 1, MAX_NUMBER));
        require(text(value, "sourceCommit").matches("[a-f0-9]{40}"), "Invalid source commit");
        sha(value.get("nativeSourceHash"));
        JSONArray files = value.getJSONArray("files");
        require(files.length() >= 2 && files.length() <= 8192, "Incomplete release-set inventory");
        String last = "";
        Set<String> names = new HashSet<>(), roles = new HashSet<>();
        long total = 0;
        boolean nativeEntry = false;
        for (int index = 0; index < files.length(); ++index) {
            JSONObject file = files.getJSONObject(index);
            keys(file, "path", "role", "size", "sha256");
            String name = relative(text(file, "path")), role = text(file, "role");
            require(name.compareTo(last) > 0 && names.add(name.toLowerCase(java.util.Locale.ROOT)), "Duplicate or unsorted path");
            last = name;
            total += number(file.get("size"), 1, 8L * 1024 * 1024 * 1024);
            sha(file.get("sha256"));
            require((role.equals("native") && name.equals("libUnreal.so")) ||
                    (role.equals("content") && name.matches("Content/Paks/[A-Za-z0-9_.-]+\\.pak")), "Artifact outside frozen APK shell");
            nativeEntry |= role.equals("native");
            roles.add(role);
        }
        require(nativeEntry && roles.contains("content") && total <= 32L * 1024 * 1024 * 1024, "Incomplete or oversized release set");
        savePolicy(value.getJSONObject("save"));
        require(sha(value.get("buildId")).equals(buildId(value)), "Native/content/save build binding differs");
        return value;
    }

    private static void collect(File root, File directory, Set<String> names) throws Exception {
        require(directory.getAbsoluteFile().equals(directory.getCanonicalFile()), "Aliased inventory directory");
        File[] children = directory.listFiles();
        require(children != null, "Cannot list complete inventory");
        for (File file : children) {
            require(file.getAbsoluteFile().equals(file.getCanonicalFile()), "Aliased inventory file");
            if (file.isDirectory()) collect(root, file, names);
            else {
                require(file.isFile(), "Not an ordinary file");
                names.add(root.toURI().relativize(file.toURI()).getPath());
            }
        }
    }

    private static void verifyTree(File root, JSONArray records, boolean metadata) throws Exception {
        Set<String> actual = new HashSet<>(), expected = new HashSet<>();
        collect(root, root, actual);
        if (metadata) { expected.add("manifest.json"); expected.add("manifest.sig"); }
        for (int index = 0; index < records.length(); ++index) {
            JSONObject item = records.getJSONObject(index);
            String name = text(item, "path");
            expected.add(name);
            File file = child(root, name);
            require(file.isFile() && file.length() == number(item.get("size"), 1, 8L * 1024 * 1024 * 1024)
                    && hash(file).equals(text(item, "sha256")), "Release artifact mismatch: " + name);
        }
        require(actual.equals(expected), "Release tree differs from signed inventory");
    }

    private static void forkSaves(File source, File destination) throws Exception {
        require(!destination.exists(), "Save generation already exists");
        mkdir(destination);
        if (source == null) return;
        Set<String> names = new java.util.TreeSet<>();
        collect(source, source, names);
        require(names.size() <= 4096, "Too many save files");
        long total = 0;
        for (String name : names) total += child(source, name).length();
        require(total <= 256L * 1024 * 1024 && destination.getUsableSpace() >= total + 16L * 1024 * 1024, "Save fork exceeds budget");
        for (String name : names) {
            File old = child(source, name), target = child(destination, name);
            String expected = hash(old);
            copy(old, target);
            require(hash(target).equals(expected) && hash(old).equals(expected), "Save changed during cold snapshot");
        }
    }

    /** Caller keeps this OS lease until its selected game process has stopped. */
    public static final class Store implements Closeable {
        private final File root, versions, saves;
        private final JSONObject trust;
        private final Verifier verifier;
        private final RandomAccessFile leaseFile;
        private final FileLock lease;
        private boolean closed;
        private boolean processSelected;

        public Store(File directory, JSONObject trusted, Verifier verify) throws Exception {
            root = directory.getAbsoluteFile();
            mkdir(root);
            trust = parse(canonical(trusted).getBytes(StandardCharsets.UTF_8), MAX_MANIFEST);
            sha(trust.get("baseManifestSha256"));
            verifier = verify;
            versions = child(root, "versions"); saves = child(root, "saves");
            mkdir(versions); mkdir(saves);
            leaseFile = new RandomAccessFile(child(root, "lease.lock"), "rw");
            FileLock acquired;
            try {
                acquired = leaseFile.getChannel().tryLock();
                require(acquired != null, "Another release-set process holds the lease");
            } catch (Exception error) {
                leaseFile.close();
                throw error;
            }
            lease = acquired;
        }

        @Override public void close() throws IOException {
            if (closed) return;
            closed = true;
            try { lease.release(); } finally { leaseFile.close(); }
        }

        private void held() throws Exception { require(!closed && lease.isValid(), "Cold-start OS lease required"); }
        private long baseId() throws Exception { return number(trust.get("baseReleaseId"), 1, MAX_NUMBER); }
        private File version(long release) throws Exception { require(release >= baseId(), "Invalid cached release"); return child(versions, Long.toString(release)); }

        private void writeState(JSONObject state) throws Exception {
            held();
            byte[] raw = canonical(state).getBytes(StandardCharsets.UTF_8);
            require(raw.length <= 65536, "State exceeds bound");
            AtomicFile file = new AtomicFile(child(root, "state.json"));
            FileOutputStream output = null;
            try {
                output = file.startWrite();
                output.write(raw); output.getFD().sync(); file.finishWrite(output);
            } catch (Exception error) {
                if (output != null) file.failWrite(output);
                throw error;
            }
            require(Arrays.equals(raw, readAtomic(file)), "Atomic state failed readback");
        }

        private byte[] readAtomic(AtomicFile file) throws Exception {
            try (FileInputStream input = file.openRead(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192]; int count;
                while ((count = input.read(buffer)) != -1) {
                    require(output.size() <= 65536 - count, "State exceeds bound"); output.write(buffer, 0, count);
                }
                return output.toByteArray();
            }
        }

        private JSONObject reference(JSONObject ref) throws Exception {
            keys(ref, "releaseId", "manifestSha256", "saveGeneration");
            number(ref.get("releaseId"), baseId(), MAX_NUMBER); sha(ref.get("manifestSha256"));
            require(text(ref, "saveGeneration").matches("g-[a-f0-9]{32}"), "Invalid save generation");
            return ref;
        }

        public JSONObject state() throws Exception {
            held();
            return validatedState(readAtomic(new AtomicFile(child(root, "state.json"))));
        }

        private JSONObject validatedState(byte[] raw) throws Exception {
            JSONObject state = parse(raw, 65536);
            keys(state, "format", "base", "active", "previous", "highestReleaseId", "blocked", "boot");
            number(state.get("format"), 1, 1);
            JSONObject base = reference(state.getJSONObject("base")), active = reference(state.getJSONObject("active"));
            require(number(base.get("releaseId"), 1, MAX_NUMBER) == baseId() && text(base, "manifestSha256").equals(text(trust, "baseManifestSha256")), "State belongs to another base");
            long selected = number(active.get("releaseId"), baseId(), MAX_NUMBER);
            long highest = number(state.get("highestReleaseId"), selected, MAX_NUMBER);
            if (!state.isNull("previous")) require(number(reference(state.getJSONObject("previous")).get("releaseId"), baseId(), MAX_NUMBER) < selected, "Invalid previous release order");
            JSONArray blocked = state.getJSONArray("blocked");
            require(blocked.length() <= 1024, "Blocked history exceeds bound");
            long last = baseId();
            for (int index = 0; index < blocked.length(); ++index) {
                long id = number(blocked.get(index), baseId() + 1, highest);
                require(id > last && id != selected, "Invalid blocked release order"); last = id;
            }
            if (!state.isNull("boot")) {
                JSONObject boot = state.getJSONObject("boot"); keys(boot, "attemptId", "selection");
                require(text(boot, "attemptId").matches("[a-f0-9]{32}") && canonical(boot.getJSONObject("selection")).equals(canonical(active)), "Boot/set identity mismatch");
            }
            return state;
        }

        private JSONObject readVersion(long release) throws Exception {
            return readVersion(release, true);
        }

        private JSONObject readVersion(long release, boolean verifyPayload) throws Exception {
            File directory = version(release);
            byte[] raw = read(child(directory, "manifest.json"), MAX_MANIFEST), signed = read(child(directory, "manifest.sig"), 8192);
            if (release == baseId()) require(hash(raw).equals(text(trust, "baseManifestSha256")), "Pinned base manifest differs");
            else verifier.verify(raw, signed);
            JSONObject value = manifest(raw, trust);
            require(number(value.get("releaseId"), baseId(), MAX_NUMBER) == release, "Cached release identity differs");
            if (verifyPayload) verifyTree(directory, value.getJSONArray("files"), true);
            return value;
        }

        /** Copy-only handover. Even AtomicFile backup recovery must not modify the old store. */
        public JSONObject confirmedSaveSource(JSONArray readable) throws Exception {
            held();
            File backup = child(root, "state.json.bak");
            JSONObject current = validatedState(read(backup.exists() ? backup : child(root, "state.json"), 65536));
            boolean pending = !current.isNull("boot");
            JSONObject ref = pending ? current.getJSONObject(current.isNull("previous") ? "base" : "previous") : current.getJSONObject("active");
            long release = number(ref.get("releaseId"), baseId(), MAX_NUMBER);
            JSONObject value = readVersion(release, false);
            require(hash(read(child(version(release), "manifest.json"), MAX_MANIFEST)).equals(text(ref, "manifestSha256")), "Imported save manifest differs");
            long schema = number(value.getJSONObject("save").get("schema"), 0, 10000); boolean compatible = false;
            for (int index = 0; index < readable.length(); ++index) compatible |= number(readable.get(index), 0, 10000) == schema;
            require(compatible, "New base cannot read confirmed save schema");
            File saveRoot = child(saves, text(ref, "saveGeneration"));
            require(saveRoot.isDirectory() && saveRoot.getAbsoluteFile().equals(saveRoot.getCanonicalFile()), "Imported save generation missing or aliased");
            return new JSONObject().put("reference", ref).put("savesRoot", saveRoot.getPath()).put("saveSchema", schema).put("pendingBootSkipped", pending);
        }

        private JSONObject selection(JSONObject ref) throws Exception {
            reference(ref);
            long release = number(ref.get("releaseId"), baseId(), MAX_NUMBER);
            JSONObject value = readVersion(release);
            require(hash(read(child(version(release), "manifest.json"), MAX_MANIFEST)).equals(text(ref, "manifestSha256")), "Selected manifest differs");
            File saveRoot = child(saves, text(ref, "saveGeneration")); require(saveRoot.isDirectory(), "Save generation missing");
            return new JSONObject().put("reference", ref).put("manifest", value).put("payloadRoot", version(release).getPath()).put("savesRoot", saveRoot.getPath());
        }

        private JSONObject copyVersion(File source, byte[] raw, byte[] signed) throws Exception {
            JSONObject value = manifest(raw, trust);
            JSONArray records = value.getJSONArray("files"); verifyTree(source, records, false);
            long id = number(value.get("releaseId"), baseId(), MAX_NUMBER);
            File destination = version(id);
            if (destination.exists()) {
                require(Arrays.equals(raw, read(child(destination, "manifest.json"), MAX_MANIFEST)) && Arrays.equals(signed, read(child(destination, "manifest.sig"), 8192)), "Release IDs are immutable");
                return readVersion(id);
            }
            long bytes = 32L * 1024 * 1024;
            for (int index = 0; index < records.length(); ++index) bytes += number(records.getJSONObject(index).get("size"), 1, 8L * 1024 * 1024 * 1024);
            require(root.getUsableSpace() >= bytes, "Insufficient disk for full release");
            File stage = child(versions, "stage-" + UUID.randomUUID().toString().replace("-", "")); mkdir(stage);
            for (int index = 0; index < records.length(); ++index) {
                String name = text(records.getJSONObject(index), "path"); copy(child(source, name), child(stage, name));
            }
            verifyTree(stage, records, false);
            writeNew(child(stage, "manifest.json"), raw); writeNew(child(stage, "manifest.sig"), signed);
            require(stage.renameTo(destination), "Cannot commit immutable release directory");
            return readVersion(id);
        }

        public JSONObject initialize(File source, byte[] raw, File legacySaves) throws Exception {
            held();
            require(!child(root, "state.json").exists() && !child(root, "state.json.bak").exists(), "Store already initialized");
            require(hash(raw).equals(text(trust, "baseManifestSha256")), "Base manifest is not pinned");
            JSONObject value = manifest(raw, trust); require(number(value.get("releaseId"), 1, MAX_NUMBER) == baseId(), "Expected installed base");
            copyVersion(source, raw, new byte[0]);
            String generation = "g-" + UUID.randomUUID().toString().replace("-", ""); forkSaves(legacySaves, child(saves, generation));
            JSONObject ref = new JSONObject().put("releaseId", baseId()).put("manifestSha256", text(trust, "baseManifestSha256")).put("saveGeneration", generation);
            writeState(new JSONObject().put("format", 1).put("base", ref).put("active", ref).put("previous", JSONObject.NULL)
                    .put("highestReleaseId", baseId()).put("blocked", new JSONArray()).put("boot", JSONObject.NULL));
            return selection(ref);
        }

        public long stage(File source, byte[] raw, byte[] signed) throws Exception {
            held(); verifier.verify(raw, signed);
            JSONObject value = manifest(raw, trust), current = state();
            long release = number(value.get("releaseId"), baseId() + 1, MAX_NUMBER);
            require(release > number(current.get("highestReleaseId"), baseId(), MAX_NUMBER), "Stale or blocked release");
            copyVersion(source, raw, signed); return release;
        }

        public JSONObject activate(long release) throws Exception {
            JSONObject state = state();
            require(!processSelected, "Process already selected a native/content pair; restart before activation");
            require(state.isNull("boot") && release > number(state.get("highestReleaseId"), baseId(), MAX_NUMBER), "Pending boot or stale candidate");
            JSONObject old = selection(state.getJSONObject("active")), candidate = readVersion(release);
            long schema = number(old.getJSONObject("manifest").getJSONObject("save").get("schema"), 0, 10000);
            JSONArray readable = candidate.getJSONObject("save").getJSONArray("readable"); boolean compatible = false;
            for (int index = 0; index < readable.length(); ++index) compatible |= number(readable.get(index), 0, 10000) == schema;
            require(compatible, "No save migration path for selected generation");
            String generation = "g-" + UUID.randomUUID().toString().replace("-", ""); forkSaves(new File(text(old, "savesRoot")), child(saves, generation));
            JSONObject ref = new JSONObject().put("releaseId", release).put("manifestSha256", hash(read(child(version(release), "manifest.json"), MAX_MANIFEST))).put("saveGeneration", generation);
            state.put("previous", state.getJSONObject("active")).put("active", ref).put("highestReleaseId", release); writeState(state);
            return selection(ref);
        }

        /** Reject a damaged staged pair before this process has selected any native library. */
        public JSONObject rejectStaged(long release) throws Exception {
            require(!processSelected, "A running native/content pair cannot reject and select again");
            JSONObject state = state();
            require(state.isNull("boot") && release > number(state.get("highestReleaseId"), baseId(), MAX_NUMBER)
                    && release <= MAX_NUMBER, "Pending boot or stale staged rejection");
            // A rejected download must never replace the currently verified complete set.
            selection(state.getJSONObject("active"));
            JSONArray blocked = state.getJSONArray("blocked");
            require(blocked.length() < 1024, "New baseline required: blocked history is full");
            blocked.put(release); state.put("highestReleaseId", release).put("blocked", blocked);
            writeState(state); return state;
        }

        private JSONObject rollback(JSONObject state) throws Exception {
            long failed = number(state.getJSONObject("active").get("releaseId"), baseId(), MAX_NUMBER);
            JSONObject fallback = state.isNull("previous") ? state.getJSONObject("base") : state.getJSONObject("previous");
            try { selection(fallback); } catch (Exception error) { fallback = state.getJSONObject("base"); selection(fallback); }
            Set<Long> blocked = new java.util.TreeSet<>(); JSONArray old = state.getJSONArray("blocked");
            for (int index = 0; index < old.length(); ++index) blocked.add(number(old.get(index), baseId() + 1, MAX_NUMBER));
            if (failed != baseId()) blocked.add(failed);
            require(blocked.size() <= 1024, "New baseline required: blocked history is full");
            JSONArray array = new JSONArray(); for (long id : blocked) array.put(id);
            state.put("active", fallback).put("previous", JSONObject.NULL).put("blocked", array).put("boot", JSONObject.NULL); writeState(state); return state;
        }

        /** Repair an interrupted previous process before considering a staged candidate. */
        public JSONObject recover() throws Exception {
            require(!processSelected, "Cannot select another native/content pair in the same process");
            JSONObject state = state();
            if (!state.isNull("boot")) state = rollback(state);
            try { selection(state.getJSONObject("active")); }
            catch (Exception error) {
                require(!canonical(state.getJSONObject("active")).equals(canonical(state.getJSONObject("base"))), "Installed base damaged; repair installation");
                state = rollback(state);
            }
            return state;
        }

        public JSONObject boot() throws Exception {
            JSONObject state = recover();
            JSONObject selected = selection(state.getJSONObject("active"));
            String attempt = UUID.randomUUID().toString().replace("-", "");
            state.put("boot", new JSONObject().put("attemptId", attempt).put("selection", state.getJSONObject("active"))); writeState(state);
            processSelected = true;
            return selected.put("attemptId", attempt);
        }

        public JSONObject confirm(String attempt, long release, String manifestSha, long schema) throws Exception {
            JSONObject state = state();
            require(!state.isNull("boot") && text(state.getJSONObject("boot"), "attemptId").equals(attempt), "Health belongs to another boot");
            JSONObject ref = state.getJSONObject("active");
            require(number(ref.get("releaseId"), baseId(), MAX_NUMBER) == release && text(ref, "manifestSha256").equals(sha(manifestSha)), "Health belongs to another set");
            JSONObject selected = selection(ref);
            require(schema == number(selected.getJSONObject("manifest").getJSONObject("save").get("schema"), 0, 10000), "Save migration not ready");
            state.put("boot", JSONObject.NULL); writeState(state); return selected;
        }

        public JSONObject reject(String attempt) throws Exception {
            JSONObject state = state();
            require(!state.isNull("boot") && text(state.getJSONObject("boot"), "attemptId").equals(attempt), "Failure belongs to another boot");
            return selection(rollback(state).getJSONObject("active"));
        }
    }
}
