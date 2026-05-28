using System.Reflection;
using System.Windows;

// ── Assembly identity ─────────────────────────────────────────────────────────
[assembly: AssemblyTitle("CsirtParser")]
[assembly: AssemblyDescription("UAC log parser and forensic triage tool for DFIR analysts")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("CsirtParser")]
[assembly: AssemblyCopyright("")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// ── Version ───────────────────────────────────────────────────────────────────
// MAJOR.MINOR.PATCH.BUILD
// Bump MINOR for new parsers/features, PATCH for bug fixes.
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]

// ── WPF theme resource locations ─────────────────────────────────────────────
[assembly: ThemeInfo(
    ResourceDictionaryLocation.None,            // theme-specific resource dictionaries
                                                // (used if a resource is not found in the page
                                                // or application resource dictionaries)
    ResourceDictionaryLocation.SourceAssembly   // generic resource dictionary
                                                // (used if a resource is not found in the page,
                                                // app, or any theme specific resource dictionaries)
)]