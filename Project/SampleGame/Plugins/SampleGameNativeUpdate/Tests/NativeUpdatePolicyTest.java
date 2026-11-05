package com.example.samplegame.update;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

/** Host-only test keys are generated in memory; no release key or APK certificate is read. */
public final class NativeUpdatePolicyTest {
    private static int checks;
    interface Action { void run() throws Exception; }

    private static void check(boolean condition, String name) {
        ++checks;
        if (!condition) throw new AssertionError(name);
    }

    private static void rejects(Action action, String name) throws Exception {
        boolean rejected = false;
        try { action.run(); }
        catch (Exception error) { rejected = true; }
        check(rejected, name);
    }

    private static byte[] elf(int machine, long alignment, long offset, long size, long flags) {
        ByteBuffer output = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN);
        output.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, 1, 1 });
        output.position(16);
        output.putShort((short) 3).putShort((short) machine).putInt(1).putLong(0).putLong(64).putLong(0).putInt(0);
        output.putShort((short) 64).putShort((short) 56).putShort((short) 1).putShort((short) 0).putShort((short) 0).putShort((short) 0);
        output.position(64);
        output.putInt(1).putInt((int) flags).putLong(offset).putLong(0).putLong(0).putLong(size).putLong(size).putLong(alignment);
        return output.array();
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = "{\"format\":1,\"releaseId\":301}".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(payload);
        byte[] signature = signer.sign();
        NativeUpdatePolicy.verifySignature(payload, signature, "SHA256withRSA", pair.getPublic());
        check(true, "Valid RSA signed payload");
        byte[] changed = payload.clone();
        changed[2] ^= 1;
        rejects(() -> NativeUpdatePolicy.verifySignature(changed, signature, "SHA256withRSA", pair.getPublic()), "Tampered payload");
        byte[] changedSignature = signature.clone();
        changedSignature[1] ^= 1;
        rejects(() -> NativeUpdatePolicy.verifySignature(payload, changedSignature, "SHA256withRSA", pair.getPublic()), "Tampered signature");
        rejects(() -> NativeUpdatePolicy.verifySignature(payload, signature, "NONEwithRSA", pair.getPublic()), "Algorithm downgrade");
        KeyPair other = generator.generateKeyPair();
        rejects(() -> NativeUpdatePolicy.verifySignature(payload, signature, "SHA256withRSA", other.getPublic()), "Different signer");
        rejects(() -> NativeUpdatePolicy.verifySignature(new byte[32769], signature, "SHA256withRSA", pair.getPublic()), "Oversized payload");
        rejects(() -> NativeUpdatePolicy.verifySignature(new byte[0], signature, "SHA256withRSA", pair.getPublic()), "Empty payload");

        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(256);
        KeyPair ec = ecGenerator.generateKeyPair();
        Signature ecSigner = Signature.getInstance("SHA256withECDSA");
        ecSigner.initSign(ec.getPrivate());
        ecSigner.update(payload);
        NativeUpdatePolicy.verifySignature(payload, ecSigner.sign(), "SHA256withECDSA", ec.getPublic());
        check(true, "Valid ECDSA signed payload");
        rejects(() -> NativeUpdatePolicy.verifySignature(payload, signature, "SHA256withRSA", ec.getPublic()), "Signer key type mismatch");

        NativeUpdatePolicy.requireSameOrigin("https://updates.example.com/game/manifest.json", "https://updates.example.com/native/r1.so");
        check(true, "Same HTTPS origin");
        rejects(() -> NativeUpdatePolicy.requireHttps("http://updates.example.com/file"), "Plain HTTP");
        rejects(() -> NativeUpdatePolicy.requireHttps("https://user:pass@updates.example.com/file"), "URL user info");
        rejects(() -> NativeUpdatePolicy.requireHttps("https://updates.example.com:8443/file"), "Unexpected port");
        rejects(() -> NativeUpdatePolicy.requireHttps("https://updates.example.com/a/../b"), "Non-normalized URL");
        rejects(() -> NativeUpdatePolicy.requireSameOrigin("https://updates.example.com/m.json", "https://other.example/r.so"), "Cross-origin payload");

        File directory = Files.createTempDirectory("native-policy-test-").toFile();
        File valid = new File(directory, "libUnreal.so");
        try {
            check(NativeUpdatePolicy.child(directory, "libUnreal.so").equals(valid), "Private child path");
            rejects(() -> NativeUpdatePolicy.child(directory, "../libUnreal.so"), "Path traversal");
            rejects(() -> NativeUpdatePolicy.child(directory, ".."), "Parent path");
            rejects(() -> NativeUpdatePolicy.child(directory, "a/b"), "Nested path");
            byte[] good = elf(183, 16384, 0, 256, 5);
            Files.write(valid.toPath(), good);
            NativeUpdatePolicy.verifyElf(valid);
            check(true, "16 KiB AArch64 ELF");
            String hash = NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(good));
            NativeUpdatePolicy.verifyFile(valid, good.length, hash);
            check(true, "Streaming file hash and ELF");
            rejects(() -> NativeUpdatePolicy.verifyFile(valid, good.length + 1, hash), "File size differs");
            rejects(() -> NativeUpdatePolicy.verifyFile(valid, good.length, "0".repeat(64)), "File hash differs");
            rejects(() -> NativeUpdatePolicy.verifyFile(valid, NativeUpdatePolicy.MAX_SO_BYTES + 1, hash), "Unbounded payload");
            rejects(() -> NativeUpdatePolicy.requireSha256("A".repeat(64)), "Noncanonical SHA256");
            Files.write(valid.toPath(), elf(62, 16384, 0, 256, 5));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "x86 ELF rejected on ARM64");
            Files.write(valid.toPath(), elf(183, 4096, 0, 256, 5));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "4 KiB LOAD rejected");
            Files.write(valid.toPath(), elf(183, 24576, 0, 256, 5));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "Non-power-of-two alignment");
            Files.write(valid.toPath(), elf(183, 16384, 1, 128, 5));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "LOAD offset alignment differs");
            Files.write(valid.toPath(), elf(183, 16384, 0, 257, 5));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "LOAD beyond file end");
            Files.write(valid.toPath(), elf(183, 16384, 0, 256, 7));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "Writable executable LOAD");
            Files.write(valid.toPath(), elf(183, 16384, 0, 256, 4));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "No executable LOAD");
            Files.write(valid.toPath(), Arrays.copyOf(good, 63));
            rejects(() -> NativeUpdatePolicy.verifyElf(valid), "Truncated ELF header");
        } finally {
            Files.deleteIfExists(valid.toPath());
            Files.delete(directory.toPath());
        }
        System.out.println("NativeUpdatePolicyTest: " + checks + " checks passed");
    }
}
