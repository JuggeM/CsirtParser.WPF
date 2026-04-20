using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Extracts .tar.gz archives using ONLY built-in .NET libraries.
    /// Handles illegal Windows filename characters by sanitizing them.
    /// Creates flat structure: Decompressed/uac-name/ (not Decompressed/uac-name/uac-name/)
    /// </summary>
    public static class ArchiveExtractor
    {
        // Characters that are illegal in Windows filenames
        private static readonly char[] IllegalChars = new[] { '<', '>', ':', '"', '|', '?', '*' };
        private static readonly string IllegalCharsPattern = $"[{Regex.Escape(new string(IllegalChars))}]";

        /// <summary>
        /// Extract all .tar.gz files from Upload folder
        /// </summary>
        public static List<string> ExtractAllFromFolder(
            string uploadFolder,
            string decompressedRoot,
            Action<string> statusCallback = null)
        {
            var extractedFolders = new List<string>();

            if (!Directory.Exists(uploadFolder))
            {
                statusCallback?.Invoke($"Upload folder not found: {uploadFolder}");
                return extractedFolders;
            }

            Directory.CreateDirectory(decompressedRoot);

            var gzFiles = new List<string>();
            gzFiles.AddRange(Directory.GetFiles(uploadFolder, "*.tar.gz", SearchOption.AllDirectories));
            gzFiles.AddRange(Directory.GetFiles(uploadFolder, "*.tgz", SearchOption.AllDirectories));

            if (gzFiles.Count == 0)
            {
                statusCallback?.Invoke("No .tar.gz archives found in Upload folder");
                return extractedFolders;
            }

            statusCallback?.Invoke($"Found {gzFiles.Count} archive(s) to process");

            foreach (var gzFile in gzFiles)
            {
                string extractedPath = ExtractTarGz(gzFile, decompressedRoot, statusCallback);
                if (!string.IsNullOrEmpty(extractedPath))
                    extractedFolders.Add(extractedPath);
            }

            return extractedFolders;
        }

        /// <summary>
        /// Extract a .tar.gz file to Decompressed/collection-name/
        /// Automatically flattens nested folders and sanitizes illegal filenames
        /// </summary>
        public static string ExtractTarGz(string gzFilePath, string decompressedRoot, Action<string> statusCallback = null)
        {
            if (!File.Exists(gzFilePath))
            {
                statusCallback?.Invoke($"File not found: {gzFilePath}");
                return null;
            }

            string fileName = Path.GetFileNameWithoutExtension(gzFilePath);
            if (fileName.EndsWith(".tar", StringComparison.OrdinalIgnoreCase))
                fileName = Path.GetFileNameWithoutExtension(fileName);

            string collectionName = fileName;
            string targetFolder = Path.Combine(decompressedRoot, collectionName);

            if (Directory.Exists(targetFolder))
            {
                var existingFiles = Directory.GetFileSystemEntries(targetFolder);
                if (existingFiles.Length > 0)
                {
                    statusCallback?.Invoke($"Skipping - already extracted: {collectionName}");
                    return targetFolder;
                }
            }

            try
            {
                statusCallback?.Invoke($"Extracting {Path.GetFileName(gzFilePath)}...");
                Directory.CreateDirectory(targetFolder);

                string tempTarPath = Path.Combine(Path.GetTempPath(), "temp_" + Guid.NewGuid().ToString("N") + ".tar");

                statusCallback?.Invoke($"  Decompressing .gz...");
                using (FileStream gzStream = File.OpenRead(gzFilePath))
                using (GZipStream decompressionStream = new GZipStream(gzStream, CompressionMode.Decompress))
                using (FileStream tarStream = File.Create(tempTarPath))
                {
                    decompressionStream.CopyTo(tarStream);
                }

                statusCallback?.Invoke($"  Extracting .tar archive...");
                var extractedPaths = ExtractTar(tempTarPath, targetFolder, statusCallback);

                FlattenIfNested(targetFolder, extractedPaths, statusCallback);

                if (File.Exists(tempTarPath))
                    File.Delete(tempTarPath);

                statusCallback?.Invoke($"Extracted: {collectionName}");
                return targetFolder;
            }
            catch (Exception ex)
            {
                statusCallback?.Invoke($"ERROR extracting {collectionName}: {ex.Message}");

                try
                {
                    if (Directory.Exists(targetFolder))
                        Directory.Delete(targetFolder, recursive: true);
                }
                catch { }

                return null;
            }
        }

        /// <summary>
        /// Sanitize a single path component to be Windows-compatible
        /// </summary>
        private static string SanitizePathComponent(string component)
        {
            if (string.IsNullOrWhiteSpace(component))
                return component;

            // Remove brackets (common: [root])
            component = component.Replace("[", "").Replace("]", "");

            // Replace illegal Windows characters with underscore
            component = Regex.Replace(component, IllegalCharsPattern, "_");

            // Replace non-printable and problematic Unicode characters
            // Keep only ASCII printable characters and common safe Unicode
            var sb = new StringBuilder(component.Length);
            foreach (char c in component)
            {
                if ((c >= 0x20 && c <= 0x7E) ||  // ASCII printable
                    c == ' ' || c == '-' || c == '_' || c == '.')  // Safe chars
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append('_');  // Replace problematic chars
                }
            }
            component = sb.ToString();

            // Replace multiple underscores with single
            component = Regex.Replace(component, @"_{2,}", "_");

            // Trim dots and spaces from end (Windows doesn't allow)
            component = component.TrimEnd('.', ' ');

            // Ensure not empty after sanitization
            if (string.IsNullOrWhiteSpace(component))
                component = "file";

            return component;
        }

        /// <summary>
        /// Extract a .tar file (reads TAR format directly)
        /// Returns list of all extracted relative paths
        /// </summary>
        private static List<string> ExtractTar(string tarPath, string targetFolder, Action<string> statusCallback)
        {
            var extractedPaths = new List<string>();
            int skippedFiles = 0;

            using (FileStream stream = File.OpenRead(tarPath))
            {
                while (stream.Position < stream.Length)
                {
                    byte[] header = new byte[512];
                    int bytesRead = stream.Read(header, 0, 512);

                    if (bytesRead < 512)
                        break;

                    bool isZero = true;
                    for (int i = 0; i < 512; i++)
                    {
                        if (header[i] != 0)
                        {
                            isZero = false;
                            break;
                        }
                    }

                    if (isZero)
                        break;

                    string fileName = GetTarString(header, 0, 100).Trim('\0').Trim();
                    if (string.IsNullOrWhiteSpace(fileName))
                        break;

                    string fileSizeStr = GetTarString(header, 124, 12).Trim('\0').Trim();
                    long fileSize = ParseOctal(fileSizeStr);

                    char typeFlag = (char)header[156];

                    extractedPaths.Add(fileName);

                    // Handle files (not directories)
                    if (typeFlag != '5' && !fileName.EndsWith("/"))
                    {
                        try
                        {
                            // Split path into components and sanitize EACH ONE
                            string[] pathParts = fileName.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
                            string[] sanitizedParts = pathParts.Select(p => SanitizePathComponent(p)).ToArray();

                            // Build path piece by piece to avoid Path.Combine issues
                            string fullPath = targetFolder;
                            foreach (string part in sanitizedParts)
                            {
                                fullPath = Path.Combine(fullPath, part);
                            }

                            // Check path length (Windows MAX_PATH = 260)
                            if (fullPath.Length >= 250)  // Leave some margin
                            {
                                skippedFiles++;
                                SkipFileData(stream, fileSize);
                                continue;
                            }

                            // Create directory
                            string directory = Path.GetDirectoryName(fullPath);
                            if (!string.IsNullOrEmpty(directory))
                            {
                                try
                                {
                                    Directory.CreateDirectory(directory);
                                }
                                catch
                                {
                                    skippedFiles++;
                                    SkipFileData(stream, fileSize);
                                    continue;
                                }
                            }

                            // Extract file
                            using (FileStream outputFile = File.Create(fullPath))
                            {
                                long remaining = fileSize;
                                byte[] buffer = new byte[4096];

                                while (remaining > 0)
                                {
                                    int toRead = (int)Math.Min(remaining, buffer.Length);
                                    int read = stream.Read(buffer, 0, toRead);
                                    if (read == 0)
                                        break;

                                    outputFile.Write(buffer, 0, read);
                                    remaining -= read;
                                }
                            }

                            // Skip padding to next 512-byte boundary
                            long paddingBytes = (512 - (fileSize % 512)) % 512;
                            if (paddingBytes > 0)
                                stream.Seek(paddingBytes, SeekOrigin.Current);
                        }
                        catch (Exception ex)
                        {
                            // Log but continue
                            skippedFiles++;
                            SkipFileData(stream, fileSize);
                        }
                    }
                    else
                    {
                        // Directory or special file - skip data blocks
                        long blocksToSkip = (fileSize + 511) / 512;
                        long skipBytes = blocksToSkip * 512;
                        if (skipBytes > 0)
                            stream.Seek(skipBytes, SeekOrigin.Current);
                    }
                }
            }

            if (skippedFiles > 0)
                statusCallback?.Invoke($"  Skipped {skippedFiles} file(s) with problematic names or paths");

            return extractedPaths;
        }

        /// <summary>
        /// Skip file data in stream when we can't extract it
        /// </summary>
        private static void SkipFileData(FileStream stream, long fileSize)
        {
            try
            {
                long paddingBytes = (512 - (fileSize % 512)) % 512;
                long totalSkip = fileSize + paddingBytes;
                if (totalSkip > 0 && stream.Position + totalSkip <= stream.Length)
                    stream.Seek(totalSkip, SeekOrigin.Current);
            }
            catch
            {
                // If seek fails, try reading to skip
                long remaining = fileSize;
                byte[] buffer = new byte[4096];
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(remaining, buffer.Length);
                    int read = stream.Read(buffer, 0, toRead);
                    if (read == 0) break;
                    remaining -= read;
                }
            }
        }

        /// <summary>
        /// If all extracted files are under one top-level folder, move them up
        /// </summary>
        private static void FlattenIfNested(string targetFolder, List<string> extractedPaths, Action<string> statusCallback)
        {
            if (extractedPaths.Count == 0)
                return;

            var topLevelFolders = extractedPaths
                .Select(p => p.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault())
                .Where(f => !string.IsNullOrWhiteSpace(f))
                .Select(f => SanitizePathComponent(f))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (topLevelFolders.Count == 1)
            {
                string topFolder = topLevelFolders[0];
                string nestedPath = Path.Combine(targetFolder, topFolder);

                if (Directory.Exists(nestedPath))
                {
                    try
                    {
                        statusCallback?.Invoke($"  Flattening: removing nested '{topFolder}/' folder...");

                        string tempFolder = Path.Combine(targetFolder, "_temp_" + Guid.NewGuid().ToString("N"));
                        Directory.Move(nestedPath, tempFolder);

                        foreach (var item in Directory.GetFileSystemEntries(tempFolder))
                        {
                            string itemName = Path.GetFileName(item);
                            string destPath = Path.Combine(targetFolder, itemName);

                            try
                            {
                                if (Directory.Exists(item))
                                    Directory.Move(item, destPath);
                                else
                                    File.Move(item, destPath);
                            }
                            catch
                            {
                                // Skip if can't move
                            }
                        }

                        try
                        {
                            Directory.Delete(tempFolder, recursive: true);
                        }
                        catch { }

                        statusCallback?.Invoke($"  Flattened successfully");
                    }
                    catch (Exception ex)
                    {
                        statusCallback?.Invoke($"  Warning: Could not flatten - {ex.Message}");
                    }
                }
            }
        }

        private static string GetTarString(byte[] buffer, int offset, int length)
        {
            return Encoding.ASCII.GetString(buffer, offset, length);
        }

        private static long ParseOctal(string octalString)
        {
            if (string.IsNullOrWhiteSpace(octalString))
                return 0;

            octalString = octalString.Trim();

            try
            {
                return Convert.ToInt64(octalString, 8);
            }
            catch
            {
                if (long.TryParse(octalString, out long result))
                    return result;
                return 0;
            }
        }
    }
}
