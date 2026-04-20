using System;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace Helpers
{
    /// <summary>
    /// Handles extraction of UAC .tar.gz files from Upload folder
    /// Uses built-in .NET libraries (no external packages needed)
    /// </summary>
    public static class TarGzExtractor
    {
        /// <summary>
        /// Find all UAC*.tar.gz files in Upload folder and extract them
        /// </summary>
        /// <param name="caseFolderPath">Root case folder path</param>
        /// <returns>List of extracted collection names</returns>
        public static List<string> ExtractUacArchives(string caseFolderPath)
        {
            var extractedCollections = new List<string>();

            string uploadPath = Path.Combine(caseFolderPath, "Upload");
            string decompressedPath = Path.Combine(caseFolderPath, "Decompressed");

            // Create folders if they don't exist
            if (!Directory.Exists(uploadPath))
            {
                Directory.CreateDirectory(uploadPath);
                return extractedCollections; // Empty Upload folder
            }

            if (!Directory.Exists(decompressedPath))
                Directory.CreateDirectory(decompressedPath);

            // Find all UAC .tar.gz files
            var uacFiles = Directory.GetFiles(uploadPath, "UAC*.tar.gz", SearchOption.TopDirectoryOnly);

            if (uacFiles.Length == 0)
            {
                // Also check for just .gz extension (some might not have .tar.gz)
                uacFiles = Directory.GetFiles(uploadPath, "UAC*.gz", SearchOption.TopDirectoryOnly);
            }

            foreach (var tarGzFile in uacFiles)
            {
                try
                {
                    string collectionName = ExtractSingleArchive(tarGzFile, decompressedPath);
                    if (!string.IsNullOrEmpty(collectionName))
                        extractedCollections.Add(collectionName);
                }
                catch (Exception ex)
                {
                    // Log error but continue with other files
                    Console.WriteLine($"Failed to extract {Path.GetFileName(tarGzFile)}: {ex.Message}");
                }
            }

            return extractedCollections;
        }

        /// <summary>
        /// Extract a single .tar.gz archive using built-in .NET libraries
        /// </summary>
        private static string ExtractSingleArchive(string tarGzPath, string decompressedPath)
        {
            string fileName = Path.GetFileName(tarGzPath);

            // Determine collection name (remove .tar.gz or .gz)
            string collectionName = Path.GetFileNameWithoutExtension(tarGzPath);
            if (collectionName.EndsWith(".tar", StringComparison.OrdinalIgnoreCase))
                collectionName = Path.GetFileNameWithoutExtension(collectionName);

            string extractionPath = Path.Combine(decompressedPath, collectionName);

            // Clean old extraction if exists
            if (Directory.Exists(extractionPath))
                Directory.Delete(extractionPath, recursive: true);

            Directory.CreateDirectory(extractionPath);

            // Extract .tar.gz using built-in .NET libraries
            // Step 1: Open .gz stream
            using (FileStream compressedStream = File.OpenRead(tarGzPath))
            using (GZipStream gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            {
                // Step 2: Extract TAR archive directly from decompressed stream
                TarFile.ExtractToDirectory(gzipStream, extractionPath, overwriteFiles: true);
            }

            return collectionName;
        }

        /// <summary>
        /// Get list of UAC files in Upload folder without extracting
        /// </summary>
        public static List<string> ListUacArchives(string caseFolderPath)
        {
            var files = new List<string>();
            string uploadPath = Path.Combine(caseFolderPath, "Upload");

            if (!Directory.Exists(uploadPath))
                return files;

            // Find .tar.gz files
            files.AddRange(Directory.GetFiles(uploadPath, "UAC*.tar.gz", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName));

            // Also check for .gz (in case they're not named .tar.gz)
            var gzFiles = Directory.GetFiles(uploadPath, "UAC*.gz", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName)
                .Where(f => !f.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase));

            files.AddRange(gzFiles);

            return files;
        }

        /// <summary>
        /// Check if extraction is needed (Upload has files but Decompressed is empty/missing)
        /// </summary>
        public static bool NeedsExtraction(string caseFolderPath)
        {
            string uploadPath = Path.Combine(caseFolderPath, "Upload");
            string decompressedPath = Path.Combine(caseFolderPath, "Decompressed");

            if (!Directory.Exists(uploadPath))
                return false;

            var uacFiles = ListUacArchives(caseFolderPath);
            if (uacFiles.Count == 0)
                return false;

            // If Decompressed doesn't exist or is empty, extraction needed
            if (!Directory.Exists(decompressedPath))
                return true;

            var collections = Directory.GetDirectories(decompressedPath);
            return collections.Length == 0;
        }
    }
}