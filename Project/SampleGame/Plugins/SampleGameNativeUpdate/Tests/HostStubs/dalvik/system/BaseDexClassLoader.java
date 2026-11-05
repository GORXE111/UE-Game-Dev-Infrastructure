package dalvik.system;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
public class BaseDexClassLoader extends ClassLoader {
    private final FakePathList pathList;
    public static boolean failMake;
    public static boolean denyReflection;
    public static boolean ignoreFirst;
    public BaseDexClassLoader(File originalDirectory) { pathList = new FakePathList(originalDirectory); }
    @Override public String findLibrary(String name) {
        File[] elements = pathList.nativeLibraryPathElements;
        for (int index = ignoreFirst && elements.length > 1 ? 1 : 0; index < elements.length; ++index) {
            File file = new File(elements[index], "lib" + name + ".so");
            if (file.isFile()) return file.getAbsolutePath();
        }
        return null;
    }
    private static final class FakePathList {
        private List<File> nativeLibraryDirectories = new ArrayList<>();
        private final List<File> systemNativeLibraryDirectories = new ArrayList<>();
        private File[] nativeLibraryPathElements;
        FakePathList(File original) { nativeLibraryDirectories.add(original); nativeLibraryPathElements = new File[] { original }; }
        private static File[] makePathElements(List<File> values) {
            if (denyReflection) throw new SecurityException("Injected platform reflection rejection");
            if (failMake) return new File[0];
            return values.toArray(new File[0]);
        }
    }
}
