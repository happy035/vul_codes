import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Vulnerability Pattern: Path Traversal / Directory Traversal (CWE-22 / CWE-23 / CWE-36)
 * 
 * Description:
 * Constructing a file path using unsanitized user input (such as "../" sequences)
 * allows an attacker to access arbitrary files and directories located outside
 * the intended base directory on the filesystem.
 * 
 * Target SAST / Code Mender Rule:
 * Identify filesystem access APIs (e.g., new File(), Paths.get(), FileInputStream)
 * where the target path is constructed by concatenating an untrusted input string
 * without verifying that the resolved canonical path remains within the authorized base directory.
 */
public class PathTraversal {

    private static final String BASE_DIRECTORY = "/var/data/public_reports";

    /**
     * Vulnerable: Directly appends user-supplied filename to base path without validation.
     * An input like "../../etc/passwd" or "....//....//etc/passwd" traverses outside BASE_DIRECTORY.
     */
    public static void readFileVulnerable(String userFilename) {
        try {
            File targetFile = new File(BASE_DIRECTORY, userFilename);
            System.out.println("[Vulnerable] Resolved Path: " + targetFile.getPath());

            // Unsafe: Reading file directly from the unvalidated target path
            if (targetFile.exists() && targetFile.isFile()) {
                String content = new String(Files.readAllBytes(targetFile.toPath()), StandardCharsets.UTF_8);
                System.out.println("[Vulnerable] File Content Preview:\n" + content);
            } else {
                System.out.println("[Vulnerable] File not found or is not a regular file: " + targetFile.getPath());
            }
        } catch (IOException e) {
            System.err.println("[Vulnerable] Error reading file: " + e.getMessage());
        }
    }

    /**
     * Remediation / Fix Strategy:
     * 1. Resolve and normalize the path or obtain the canonical path.
     * 2. Verify that the resolved path strictly starts with the authorized base directory path.
     * 3. Alternatively, whitelist allowed filenames or strip all directory traversal sequences.
     */
    public static void readFileFixed(String userFilename) {
        try {
            Path basePath = Paths.get(BASE_DIRECTORY).toAbsolutePath().normalize();
            Path resolvedPath = basePath.resolve(userFilename).normalize();

            // Check if the normalized path stays within the designated base directory
            if (!resolvedPath.startsWith(basePath)) {
                System.err.println("[Fixed] Security Alert: Path traversal attempt detected! Path: " + resolvedPath);
                return;
            }

            File targetFile = resolvedPath.toFile();
            if (targetFile.exists() && targetFile.isFile()) {
                String content = new String(Files.readAllBytes(resolvedPath), StandardCharsets.UTF_8);
                System.out.println("[Fixed] File Content Preview:\n" + content);
            } else {
                System.out.println("[Fixed] File not found: " + resolvedPath);
            }
        } catch (IOException e) {
            System.err.println("[Fixed] Error resolving path: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java PathTraversal <filename_or_traversal_payload>");
            System.out.println("Example: java PathTraversal ../../etc/passwd");
            return;
        }

        String userInput = args[0];
        System.out.println("=== Testing Vulnerable Method ===");
        readFileVulnerable(userInput);

        System.out.println("\n=== Testing Fixed Method ===");
        readFileFixed(userInput);
    }
}
