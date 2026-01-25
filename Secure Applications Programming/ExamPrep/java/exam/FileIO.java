package exam;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Simple file IO helpers.
 * Kept minimal for exam-style exercises: read whole file, write whole file.
 */
public final class FileIO {
    private FileIO() {}

    public static byte[] readFile(String path) throws IOException {
        Path p = Paths.get(path);
        return Files.readAllBytes(p);
    }

    public static void writeFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }
}