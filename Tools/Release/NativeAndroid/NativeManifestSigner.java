import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;

/** Release signing keeps the private key inside the existing Java KeyStore. */
public final class NativeManifestSigner {
    private static char[] password(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("Required signing password environment variable is absent");
        return value.toCharArray();
    }
    private static String hex(byte[] bytes) {
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) output.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return output.toString();
    }
    public static void main(String[] args) {
        char[] storePassword = null;
        char[] keyPassword = null;
        try {
            if (args.length != 9) throw new IllegalArgumentException("Invalid signer arguments");
            storePassword = password(args[6]);
            keyPassword = password(args[7]);
            KeyStore store = KeyStore.getInstance(Path.of(args[0]).toFile(), storePassword);
            Certificate certificate = store.getCertificate(args[1]);
            if (certificate == null || !"RSA".equals(certificate.getPublicKey().getAlgorithm()))
                throw new IllegalArgumentException("Expected the RSA release certificate");
            byte[] certificateBytes = certificate.getEncoded();
            String fingerprint = hex(MessageDigest.getInstance("SHA-256").digest(certificateBytes));
            if (!fingerprint.equals(args[8])) throw new IllegalArgumentException("Release certificate SHA256 mismatch");
            Key key = store.getKey(args[1], keyPassword);
            if (!(key instanceof PrivateKey)) throw new IllegalArgumentException("Signing alias has no private key");
            byte[] payload = Files.readAllBytes(Path.of(args[2]));
            if (payload.length == 0 || payload.length > 32768) throw new IllegalArgumentException("Signed payload size out of bounds");
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign((PrivateKey) key);
            signer.update(payload);
            byte[] signed = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(payload);
            if (!verifier.verify(signed)) throw new IllegalArgumentException("Signature self-verification failed");
            Files.write(Path.of(args[3]), signed);
            Files.write(Path.of(args[4]), certificateBytes);
            Files.writeString(Path.of(args[5]), fingerprint, java.nio.charset.StandardCharsets.US_ASCII);
            System.out.println("NATIVE_MANIFEST_SIGNED certificateSha256=" + fingerprint);
        } catch (Exception failure) {
            // Exceptions from keystore providers may include paths. Never print
            // provider details, input bytes, passwords, or private key material.
            System.err.println("Native manifest signing failed: " + failure.getClass().getSimpleName());
            System.exit(1);
        } finally {
            if (storePassword != null) Arrays.fill(storePassword, '\0');
            if (keyPassword != null) Arrays.fill(keyPassword, '\0');
        }
    }
}
