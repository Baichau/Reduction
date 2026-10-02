using System;
using System.IO;

namespace SecureRedactionHost;

internal static class HostLog
{
    public static readonly string Folder =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalRedaction", "logs");

    private static readonly string FilePath = Path.Combine(Folder, "host.log");
    private static readonly object Gate = new();

    static HostLog() => Directory.CreateDirectory(Folder);

    public static void Info(string m)  => Write("INFO",  m);
    public static void Error(string m) => Write("ERROR", m);

    private static void Write(string level, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}";
        lock (Gate)
        {
            try { System.IO.File.AppendAllText(FilePath, line + Environment.NewLine); }
            catch { /* logging must never crash the host */ }
        }
    }
}