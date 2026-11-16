using System;
using System.Collections.Generic;

namespace Helpers
{
    /// <summary>
    /// Keyword matching for command lines.
    ///
    /// Plain substring matching gives false positives on short command
    /// keywords: "nc " (netcat) matches the end of "rsync ", "curl" matches
    /// "libcurl", "php " matches "somephp ". Here a keyword that starts with a
    /// letter must also start a word in the text, so
    ///   "nc " matches "nc 1.2.3.4 4444" and "/bin/nc -e", but not "rsync -a".
    /// Keywords that start with anything else ("/tmp/", ">&2", and redirects
    /// like "0>&1" / "2>&1") match anywhere, as before. Case-insensitive.
    /// </summary>
    public static class KeywordMatcher
    {
        public static bool ContainsKeyword(string text, string keyword)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(keyword)) return false;
            bool needsWordStart = char.IsLetter(keyword[0]);

            int idx = 0;
            while ((idx = text.IndexOf(keyword, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                if (!needsWordStart || idx == 0 || !IsWordChar(text[idx - 1]))
                    return true;
                idx++;
            }
            return false;
        }

        public static bool ContainsAny(string text, IEnumerable<string> keywords)
        {
            foreach (var kw in keywords)
                if (ContainsKeyword(text, kw)) return true;
            return false;
        }

        private static bool IsWordChar(char c) =>
            char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.';
    }
}
