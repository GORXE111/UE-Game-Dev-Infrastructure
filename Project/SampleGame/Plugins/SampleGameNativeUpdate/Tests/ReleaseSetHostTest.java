package com.example.samplegame.update;

import android.util.AtomicFile;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;

/** Tiny files and Android API doubles; never a device/SO/PAK execution claim. */
public final class ReleaseSetHostTest {
    private static int checks;
    private static void check(boolean ok, String message) {
        ++checks;
        if (!ok) throw new AssertionError(message);
    }
    private interface Action { void run() throws Exception; }
    private static void rejects(Action action, String message) throws Exception {
        boolean rejected = false;
        try { action.run(); } catch (Exception error) { rejected = true; }
        check(rejected, message);
    }
    private static byte[] read(File directory, String name) throws Exception {
        return Files.readAllBytes(new File(directory, name).toPath());
    }
    private static byte[] sign(byte[] raw, KeyPair pair) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate()); signer.update(raw); return signer.sign();
    }
    private static void pair(JSONObject selected, String suffix) throws Exception {
        File root = new File(selected.getString("payloadRoot"));
        JSONArray files = selected.getJSONObject("manifest").getJSONArray("files");
        for (int index = 0; index < files.length(); ++index) {
            String content = new String(read(root, files.getJSONObject(index).getString("path")), StandardCharsets.UTF_8);
            check(content.endsWith(suffix), "Native and content must select the same version");
        }
    }
    private static void confirm(ReleaseSet.Store store, JSONObject selected) throws Exception {
        JSONObject ref = selected.getJSONObject("reference");
        store.confirm(selected.getString("attemptId"), ref.getLong("releaseId"), ref.getString("manifestSha256"), selected.getJSONObject("manifest").getJSONObject("save").getLong("schema"));
    }
    private static JSONObject trust(File fixtures) throws Exception { return ReleaseSet.parse(read(fixtures, "trust.json"), ReleaseSet.MAX_MANIFEST); }
    private static File save(JSONObject selected) throws Exception { return new File(selected.getString("savesRoot"), "ColaLabQuickSave.sav"); }

    public static void main(String[] args) throws Exception {
        File fixtures = new File(args[0]).getCanonicalFile(), output = new File(args[1]).getCanonicalFile();
        check(!output.exists() && output.mkdirs(), "Use a new host evidence directory");
        JSONObject trust = trust(fixtures);
        JSONArray vectors = new JSONObject(new String(read(fixtures, "outcomes.json"), StandardCharsets.UTF_8)).getJSONArray("vectors");
        for (int index = 0; index < vectors.length(); ++index) {
            JSONObject vector = vectors.getJSONObject(index); boolean accepted = true;
            try { ReleaseSet.manifest(read(fixtures, "vector-" + vector.getString("name") + ".json"), trust); }
            catch (Exception error) { accepted = false; }
            check(accepted == vector.getBoolean("accepted"), "Python/Java protocol parity: " + vector.getString("name"));
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        ReleaseSet.Verifier verifier = ReleaseSet.certificateVerifier(keys.getPublic(), "SHA256withRSA");
        byte[] base = read(fixtures, "100.json"), target = read(fixtures, "101.json"), signed = sign(target, keys);
        verifier.verify(target, signed);
        rejects(() -> verifier.verify(target, new byte[256]), "Reject wrong signature");
        File legacy = new File(output, "legacy"); check(legacy.mkdir(), "Legacy save directory created");
        byte[] original = "legacy-original".getBytes(StandardCharsets.UTF_8);
        Files.write(new File(legacy, "ColaLabQuickSave.sav").toPath(), original);
        File root = new File(output, "store");
        JSONObject baseSelection, targetSelection;
        try (ReleaseSet.Store store = new ReleaseSet.Store(root, trust, verifier)) {
            baseSelection = store.initialize(new File(fixtures, "payload-100"), base, legacy);
            rejects(() -> new ReleaseSet.Store(root, trust, verifier), "OS lease excludes another loader");
            confirm(store, store.boot());
            rejects(() -> store.stage(new File(fixtures, "payload-101"), target, new byte[256]), "Stage requires signature");
            store.stage(new File(fixtures, "payload-101"), target, signed);
            pair(baseSelection, "100");
            rejects(() -> store.activate(101), "A confirmed running process still cannot activate another pair");
            rejects(() -> store.boot(), "One process lease cannot select two pairs");
        }
        try (ReleaseSet.Store store = new ReleaseSet.Store(root, trust, verifier)) {
            AtomicFile.failFinishName = "state.json";
            rejects(() -> store.activate(101), "Interrupted state write rejected");
            check(store.state().getJSONObject("active").getLong("releaseId") == 100, "Interrupted commit retains old set");
            AtomicFile.silentFailFinishName = "state.json";
            rejects(() -> store.activate(101), "Silent AtomicFile commit failure detected by readback");
            check(store.state().getJSONObject("active").getLong("releaseId") == 100, "Silent failure retains old set");
            targetSelection = store.activate(101); pair(targetSelection, "101");
            check(Arrays.equals(Files.readAllBytes(save(targetSelection).toPath()), original), "Candidate initially receives exact old save bytes");
            Files.write(save(targetSelection).toPath(), "new-schema-save".getBytes(StandardCharsets.UTF_8));
            check(Arrays.equals(Files.readAllBytes(save(baseSelection).toPath()), original), "Candidate migration cannot overwrite old save");
            JSONObject firstBoot = store.boot();
            byte[] stateBeforeImport = read(root, "state.json");
            JSONObject importSource = store.confirmedSaveSource(new JSONArray().put(0).put(1));
            check(importSource.getBoolean("pendingBootSkipped") && importSource.getJSONObject("reference").getLong("releaseId") == 100, "Handover excludes unconfirmed candidate saves");
            check(Arrays.equals(stateBeforeImport, read(root, "state.json")), "Handover leaves old boot and rollback state untouched");
            rejects(() -> store.confirmedSaveSource(new JSONArray().put(1)), "New base must read the confirmed old save schema");
            rejects(() -> store.confirm("0".repeat(32), 101, firstBoot.getJSONObject("reference").getString("manifestSha256"), 1), "Stale attempt cannot confirm");
            rejects(() -> store.confirm(firstBoot.getString("attemptId"), 101, firstBoot.getJSONObject("reference").getString("manifestSha256"), 0), "Migration readiness required");
            // End this loader before confirmation. The next instance reads on-disk recovery state.
        }
        try (ReleaseSet.Store store = new ReleaseSet.Store(root, trust, verifier)) {
            JSONObject recovered = store.boot(); pair(recovered, "100");
            check(Arrays.equals(Files.readAllBytes(save(recovered).toPath()), original), "Failure restores old save generation");
            check(new String(Files.readAllBytes(save(targetSelection).toPath()), StandardCharsets.UTF_8).equals("new-schema-save"), "Failed candidate saves retained separately");
            check(store.state().getLong("highestReleaseId") == 101 && store.state().getJSONArray("blocked").getLong(0) == 101, "Rollback preserves anti-downgrade high-water mark");
            rejects(() -> store.activate(101), "Failed version cannot reactivate");
            confirm(store, recovered);
            rejects(() -> confirm(store, recovered), "Health acknowledgement cannot be replayed");
        }
        // Independently prove native/content corruption restores the whole old set.
        for (String damaged : new String[]{"libUnreal.so", "Content/Paks/SampleGame-Android.pak", "manifest.sig"}) {
            File isolated = new File(output, "damage-" + damaged.replace('/', '-'));
            try (ReleaseSet.Store store = new ReleaseSet.Store(isolated, trust, verifier)) {
                store.initialize(new File(fixtures, "payload-100"), base, legacy);
                store.stage(new File(fixtures, "payload-101"), target, signed); JSONObject candidate = store.activate(101);
                Files.write(new File(candidate.getString("payloadRoot"), damaged).toPath(), new byte[]{1, 2, 3});
                pair(store.boot(), "100");
            }
        }
        try (ReleaseSet.Store store = new ReleaseSet.Store(new File(output, "interrupted-first-import"), trust, verifier)) {
            AtomicFile.failFinishName = "state.json";
            rejects(() -> store.initialize(new File(fixtures, "payload-100"), base, legacy), "Interrupted first import leaves no selected partial set");
            JSONObject retry = store.initialize(new File(fixtures, "payload-100"), base, legacy);
            check(Arrays.equals(Files.readAllBytes(save(retry).toPath()), original), "First import safely retries verified payload and isolated saves");
            check(Arrays.equals(read(legacy, "ColaLabQuickSave.sav"), original), "Interrupted import never rewrites source progress");
        }
        File handover = new File(output, "handover");
        JSONObject selected;
        try (ReleaseSet.Store store = new ReleaseSet.Store(handover, trust, verifier)) {
            store.initialize(new File(fixtures, "payload-100"), base, legacy);
            store.stage(new File(fixtures, "payload-101"), target, signed); selected = store.activate(101);
            confirm(store, store.boot());
            File saved = new File(selected.getString("savesRoot"), "Saved/SaveGames"); check(saved.mkdirs(), "Handover save tree created");
            Files.write(new File(saved, "progress.sav").toPath(), original);
            Files.write(new File(selected.getString("payloadRoot"), "libUnreal.so").toPath(), new byte[]{1});
            check(store.confirmedSaveSource(new JSONArray().put(1)).getJSONObject("reference").getLong("releaseId") == 101, "Valid signed progress can be imported without running damaged old code");
        }
        byte[] oldState = read(handover, "state.json");
        File destination = new File(output, "new-base"); check(destination.mkdir(), "New baseline destination created");
        File snapshot = ReleasePlayer.releaseSnapshot(handover, destination, trust, new JSONArray().put(1), verifier);
        check(Arrays.equals(read(snapshot, "Saved/SaveGames/progress.sav"), original), "Cross-base snapshot preserves actual save bytes");
        check(!new File(snapshot, "ColaLabQuickSave.sav").exists(), "Cross-base snapshot contains only authored user trees");
        check(Arrays.equals(oldState, read(handover, "state.json")), "Old confirmed state remains byte-identical");
        Files.write(new File(handover, "state.json.bak").toPath(), oldState);
        try (ReleaseSet.Store store = new ReleaseSet.Store(handover, trust, verifier)) {
            store.confirmedSaveSource(new JSONArray().put(1));
            check(Arrays.equals(oldState, read(handover, "state.json.bak")), "Read-only handover never consumes AtomicFile backup");
        }
        Files.write(new File(selected.getString("payloadRoot"), "manifest.sig").toPath(), new byte[256]);
        rejects(() -> ReleasePlayer.releaseSnapshot(handover, destination, trust, new JSONArray().put(1), verifier), "Cross-base snapshot rejects untrusted old metadata");
        System.out.println("SAMPLEGAME_RELEASE_SET_HOST_OK checks=" + checks + " deviceRuntimeValidated=false");
    }
}
