using System;

namespace Helpers
{
    /// <summary>
    /// Session types for categorization
    /// </summary>
    public enum SessionType
    {
        Unknown,
        SudoCommand,        // sudo command (normal)
        CronJob,            // Scheduled task (normal)
        SshInteractive,     // Interactive SSH login
        SshFailed,          // Failed SSH attempt
        ServiceAuth,        // Service account validation
        SuCommand,          // su - user switching
        SystemdSession,     // systemd session
        PamGeneric          // Generic PAM session
    }

    /// <summary>
    /// Why this session is flagged as suspicious
    /// </summary>
    public enum SuspicionReason
    {
        None,
        UnknownIP,              // IP not in whitelist
        MultipleFailures,       // Multiple failed attempts
        ServiceAccountSSH,      // Service account trying SSH (www-data, apache, etc.)
        UnusualTime,            // 2 AM - 5 AM activity
        VeryShortWithIP,        // <1 sec but has external IP (port scan?)
        RootSSH,                // Direct root SSH (should use sudo)
        GeographicallyUnusual,  // From unexpected country
        RapidSessionPattern     // Many sessions in short time (scripted?)
    }

    public class Session
    {
        public string Username { get; set; }
        public string SourceIP { get; set; }
        public string Daemon { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int DurationSeconds { get; set; }

        // New categorization fields
        public SessionType Type { get; set; }
        public bool IsSuspicious { get; set; }
        public SuspicionReason SuspicionReason { get; set; }
        public string Notes { get; set; }

        public override string ToString()
        {
            var endTimeStr = EndTime.HasValue ? EndTime.Value.ToString("u") : "ongoing";
            var suspFlag = IsSuspicious ? "[SUSPICIOUS]" : "";
            return $"{suspFlag} User: {Username}, IP: {SourceIP}, Type: {Type}, Service: {Daemon ?? "unknown"}, Started: {StartTime:u}, Ended: {endTimeStr}, Duration: {DurationSeconds}s";
        }
    }
}
