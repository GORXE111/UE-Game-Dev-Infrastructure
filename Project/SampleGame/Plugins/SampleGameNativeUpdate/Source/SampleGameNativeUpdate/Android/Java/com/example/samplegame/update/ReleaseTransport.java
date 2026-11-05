package com.example.samplegame.update;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.MessageDigest;

/** Bounded same-origin transport. Downloading never activates a running process. */
final class ReleaseTransport {
    private final URI manifest;
    private final long deadline = System.nanoTime() + 6L * 60 * 60 * 1000000000;
    private long downloaded;

    ReleaseTransport(String url) throws Exception {
        manifest = endpoint(url);
        require(manifest.getPath().endsWith("/manifest.json"), "Expected a release manifest endpoint");
    }

    static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }

    static URI endpoint(String value) throws Exception {
        URI result = NativeUpdatePolicy.requireHttps(value);
        require(result.getQuery() == null && result.getRawPath().equals(result.getPath())
                && result.getPath().matches("/[A-Za-z0-9_./-]+")
                && !result.getPath().contains("//"), "Unsafe release endpoint");
        for (String part : result.getPath().split("/")) require(!part.equals(".") && !part.equals(".."), "Aliased endpoint");
        return result;
    }

    URI artifact(String relative) throws Exception {
        ReleaseSet.relative(relative);
        URI result = endpoint(manifest.resolve(relative).toASCIIString());
        require(result.getHost().equalsIgnoreCase(manifest.getHost())
                && result.getPath().startsWith(manifest.resolve(".").getPath()), "Release artifact escaped channel");
        return result;
    }

    private HttpsURLConnection connect(URI uri) throws Exception {
        require(System.nanoTime() < deadline, "Release transfer exceeded its deadline");
        java.net.URLConnection raw = uri.toURL().openConnection();
        require(raw instanceof HttpsURLConnection, "TLS release transport required");
        HttpsURLConnection connection = (HttpsURLConnection) raw;
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(15000);
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        connection.setRequestProperty("Accept-Encoding", "identity");
        try {
            require(connection.getResponseCode() == 200, "Release HTTP response " + connection.getResponseCode());
            String encoding = connection.getHeaderField("Content-Encoding");
            require(encoding == null || "identity".equalsIgnoreCase(encoding), "Encoded release transfer rejected");
            return connection;
        } catch (Exception error) { connection.disconnect(); throw error; }
    }

    byte[] metadata(boolean signature) throws Exception {
        URI uri = signature ? artifact("manifest.json.sig") : manifest;
        int maximum = signature ? 8192 : ReleaseSet.MAX_MANIFEST;
        HttpsURLConnection connection = connect(uri);
        try {
            long declared = connection.getContentLengthLong();
            require(declared <= maximum, "Release metadata HTTP size exceeded");
            try (InputStream input = connection.getInputStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192]; int count;
                while ((count = input.read(buffer)) != -1) {
                    require(System.nanoTime() < deadline && output.size() <= maximum - count, "Release metadata exceeds bounds");
                    output.write(buffer, 0, count);
                }
                byte[] result = output.toByteArray();
                require(result.length > 0 && (declared < 0 || declared == result.length), "Truncated release metadata");
                return result;
            }
        } finally { connection.disconnect(); }
    }

    static File child(File root, String name) throws Exception {
        ReleaseSet.relative(name);
        require(root.isDirectory() && root.getAbsoluteFile().equals(root.getCanonicalFile()), "Aliased release directory");
        File result = new File(root, name);
        require(result.getAbsoluteFile().equals(result.getCanonicalFile())
                && result.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator), "Release path escaped private root");
        return result;
    }

    static void mkdir(File directory) throws Exception {
        require(directory.isDirectory() || directory.mkdirs(), "Cannot create release directory");
        require(directory.getAbsoluteFile().equals(directory.getCanonicalFile()), "Aliased release directory");
    }

    static String hash(byte[] raw) throws Exception {
        return NativeUpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    static String hash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[262144]; int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return NativeUpdatePolicy.hex(digest.digest());
    }

    static boolean matches(File file, JSONObject record) throws Exception {
        return file.isFile() && file.length() == record.getLong("size") && hash(file).equals(record.getString("sha256"));
    }

    /** Commit only a size/hash complete file; a partial file is never a selectable payload. */
    static void copyVerified(InputStream input, File destination, JSONObject record) throws Exception {
        mkdir(destination.getParentFile());
        File temporary = new File(destination.getPath() + ".part");
        require(temporary.getAbsoluteFile().equals(temporary.getCanonicalFile()) && !temporary.isDirectory(), "Aliased partial file");
        long expected = ReleaseSet.number(record.get("size"), 1, 8L * 1024 * 1024 * 1024), received = 0;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[262144]; int count;
            while ((count = input.read(buffer)) != -1) {
                require(count <= expected - received, "Release file exceeds signed size");
                received += count; digest.update(buffer, 0, count); output.write(buffer, 0, count);
            }
            require(received == expected && NativeUpdatePolicy.hex(digest.digest()).equals(record.getString("sha256")), "Release file size/hash mismatch");
            output.getFD().sync();
        }
        require(!destination.exists() && temporary.renameTo(destination), "Cannot commit verified release file");
    }

    void payload(JSONObject value, File directory) throws Exception {
        mkdir(directory);
        JSONArray files = value.getJSONArray("files");
        long total = 64L * 1024 * 1024;
        for (int index = 0; index < files.length(); ++index) total += 2 * files.getJSONObject(index).getLong("size");
        require(directory.getUsableSpace() >= total, "Insufficient private storage for full staged release");
        for (int index = 0; index < files.length(); ++index) {
            JSONObject record = files.getJSONObject(index);
            File output = child(directory, record.getString("path"));
            if (matches(output, record)) { downloaded += output.length(); continue; }
            require(!output.exists() || (output.isFile() && output.delete()), "Cannot replace incomplete incoming file");
            URI uri = artifact("versions/" + value.getLong("releaseId") + "/payload/" + record.getString("path"));
            HttpsURLConnection connection = connect(uri);
            try {
                long declared = connection.getContentLengthLong();
                require(declared < 0 || declared == record.getLong("size"), "Release HTTP length differs from signature");
                try (InputStream input = connection.getInputStream()) {
                    InputStream boundedTime = new java.io.FilterInputStream(input) {
                        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                            require(System.nanoTime() < deadline, "Release transfer exceeded its deadline");
                            return super.read(buffer, offset, length);
                        }
                    };
                    copyVerified(boundedTime, output, record);
                }
                downloaded += output.length();
            } finally { connection.disconnect(); }
        }
    }

    long downloadedBytes() { return downloaded; }
}
