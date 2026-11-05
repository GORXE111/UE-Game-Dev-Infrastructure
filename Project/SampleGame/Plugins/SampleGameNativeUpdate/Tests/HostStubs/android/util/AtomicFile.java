package android.util;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
public class AtomicFile {
    private final File base;
    private final File backup;
    public static boolean failNextFinish;
    public static String failFinishName;
    public static String silentFailFinishName;
    public static String silentFailDeleteName;
    public AtomicFile(File file) { base = file; backup = new File(file.getPath() + ".bak"); }
    public FileInputStream openRead() throws IOException {
        if (backup.exists()) { base.delete(); if (!backup.renameTo(base)) throw new IOException("Recovery failed"); }
        return new FileInputStream(base);
    }
    public FileOutputStream startWrite() throws IOException {
        if (base.exists() && !backup.exists() && !base.renameTo(backup)) throw new IOException("Backup failed");
        return new FileOutputStream(base);
    }
    public void finishWrite(FileOutputStream output) throws IOException {
        output.close();
        if (failNextFinish || base.getName().equals(failFinishName)) {
            failNextFinish = false; failFinishName = null; throw new IOException("Injected atomic commit failure");
        }
        if (base.getName().equals(silentFailFinishName)) {
            silentFailFinishName = null;
            base.delete();
            if (backup.exists() && !backup.renameTo(base)) throw new IOException("Injected old-file preservation failed");
            return;
        }
        backup.delete();
    }
    public void failWrite(FileOutputStream output) throws IOException {
        output.close();
        base.delete();
        if (backup.exists() && !backup.renameTo(base)) throw new IOException("Rollback failed");
    }
    public void delete() {
        if (base.getName().equals(silentFailDeleteName)) { silentFailDeleteName = null; return; }
        base.delete(); backup.delete();
    }
}
