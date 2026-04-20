namespace Helpers
{
    /// <summary>
    /// AuditCsvRow is used to store:
    /// - DateTime (as string yyyy-MM-dd HH:mm:ss)
    /// - EventType (Audit event type)
    /// - IsSuspicious ("true" / "false")
    /// - NormalizedMessage (cleaned message for CSV output)
    /// </summary>
    public class AuditCsvRow
    {
        public string DateTime { get; set; }
        public string EventType { get; set; }
        public string IsSuspicious { get; set; }
        public string NormalizedMessage { get; set; }
    }
}
