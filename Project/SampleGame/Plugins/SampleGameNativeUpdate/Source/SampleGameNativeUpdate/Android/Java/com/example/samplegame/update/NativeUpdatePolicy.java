package com.example.samplegame.update;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URI;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Locale;

/** Platform-independent validation used by the Android loader and host tests. */
public final class NativeUpdatePolicy {
    public static final long MAX_SO_BYTES = 1024L * 1024L * 1024L;
    private NativeUpdatePolicy() {}

    public static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    public static void requireSha256(String value) throws IOException {
        require(value != null && value.matches("[0-9a-f]{64}"), "Invalid SHA256");
    }

    public static String hex(byte[] bytes) {
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) output.append(String.format(Locale.ROOT, "%02x", value & 255));
        return output.toString();
    }

    public static void verifySignature(byte[] payload, byte[] signed, String algorithm, PublicKey key) throws Exception {
        require(payload.length > 0 && payload.length <= 32768, "Invalid signed payload size");
        require(signed.length > 0 && signed.length <= 8192, "Invalid signature size");
        require(("SHA256withRSA".equals(algorithm) && "RSA".equals(key.getAlgorithm()))
                || ("SHA256withECDSA".equals(algorithm) && "EC".equals(key.getAlgorithm())), "Unsupported signing algorithm");
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(key);
        verifier.update(payload);
        require(verifier.verify(signed), "Native manifest signature mismatch");
    }

    public static URI requireHttps(String value) throws Exception {
        URI uri = new URI(value);
        require("https".equals(uri.getScheme()) && uri.getHost() != null && !uri.getHost().isEmpty()
                && uri.getUserInfo() == null && uri.getFragment() == null
                && (uri.getPort() == -1 || uri.getPort() == 443) && uri.equals(uri.normalize()), "Invalid native update HTTPS URL");
        return uri;
    }

    public static void requireSameOrigin(String manifestUrl, String payloadUrl) throws Exception {
        URI manifest = requireHttps(manifestUrl);
        URI payload = requireHttps(payloadUrl);
        require(manifest.getHost().equalsIgnoreCase(payload.getHost()), "Native payload origin differs from bootstrap");
    }

    public static File child(File root, String name) throws Exception {
        require(name.matches("[A-Za-z0-9._-]+") && !name.equals(".") && !name.equals(".."), "Invalid native update filename");
        File output = new File(root, name);
        require(output.getCanonicalFile().getParentFile().equals(root.getCanonicalFile()), "Native update path escaped private root");
        return output;
    }

    public static void verifyFile(File file, long size, String expectedSha256) throws Exception {
        requireSha256(expectedSha256);
        require(size >= 64 && size <= MAX_SO_BYTES && file.isFile() && file.length() == size, "Native library size mismatch");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[262144];
        try (FileInputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        require(hex(digest.digest()).equals(expectedSha256), "Native library SHA256 mismatch");
        verifyElf(file);
    }

    private static int u16(RandomAccessFile input) throws IOException {
        return input.readUnsignedByte() | input.readUnsignedByte() << 8;
    }

    private static long u32(RandomAccessFile input) throws IOException {
        return (long) u16(input) | (long) u16(input) << 16;
    }

    private static long u64(RandomAccessFile input) throws IOException {
        long low = u32(input);
        long high = u32(input);
        require((high & 0x80000000L) == 0, "ELF integer exceeds signed file offsets");
        return low | high << 32;
    }

    public static void verifyElf(File file) throws Exception {
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            require(input.length() >= 64, "Truncated ELF");
            require(input.readInt() == 0x7f454c46 && input.readUnsignedByte() == 2
                    && input.readUnsignedByte() == 1 && input.readUnsignedByte() == 1, "Expected ELF64 little-endian");
            input.seek(16);
            require(u16(input) == 3 && u16(input) == 183, "Expected AArch64 shared library");
            require(u32(input) == 1, "Unsupported ELF version");
            input.seek(32);
            long phOffset = u64(input);
            input.seek(52);
            require(u16(input) == 64, "Invalid ELF header size");
            int phSize = u16(input);
            int phCount = u16(input);
            require(phSize == 56 && phCount > 0 && phCount <= 256 && phOffset >= 64
                    && phOffset <= input.length() - (long) phCount * phSize, "Invalid ELF program headers");
            int loads = 0;
            boolean executable = false;
            for (int index = 0; index < phCount; ++index) {
                input.seek(phOffset + (long) index * phSize);
                long type = u32(input);
                long flags = u32(input);
                long offset = u64(input);
                long address = u64(input);
                u64(input);
                long fileSize = u64(input);
                long memorySize = u64(input);
                long alignment = u64(input);
                if (type != 1) continue;
                ++loads;
                require(alignment >= 16384 && (alignment & (alignment - 1)) == 0, "ELF LOAD is not 16 KiB aligned");
                require(offset % alignment == address % alignment && fileSize <= memorySize
                        && offset <= input.length() && fileSize <= input.length() - offset, "Invalid ELF LOAD range");
                require((flags & 3) != 3, "Writable executable ELF LOAD rejected");
                executable |= (flags & 1) != 0;
            }
            require(loads > 0 && executable, "ELF has no executable LOAD");
        }
    }
}
