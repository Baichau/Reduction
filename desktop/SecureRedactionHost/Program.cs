using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SecureRedactionHost;

internal static class Program
{
    private const int WorkerPort = 8765;
    private const string HealthUrl = "http://127.0.0.1:8765/health";

    [STAThread]
    public static async Task Main()
    {
        ApplicationConfiguration.Initialize();

        using var singleInstance = new Mutex(
            initiallyOwned: true,
            name: @"Global\LocalRedactionHost_v1",
            createdNew: out bool isFirstInstance);

        if (!isFirstInstance)
        {
            OpenBrowser($"http://127.0.0.1:{WorkerPort}");
            return;
        }

        var root = FindInstallRoot();
        if (root is null)
        {
            ShowFatal("Couldn't locate the LocalRedaction install folder.", null);
            return;
        }
        ClearStaleWorkerProcesses(root);
        HostLog.Info($"Install root: {root}");

        var backendPath = Path.Combine(root, "backend");
        if (!Directory.Exists(backendPath))
        {
            ShowFatal($"Backend folder not found at:\n{backendPath}", null);
            return;
        }

        var workerCandidates = new[]
        {
            Path.Combine(root, "dist", "worker", "LocalRedactionWorker", "LocalRedactionWorker.exe"),
            Path.Combine(root, "worker", "LocalRedactionWorker", "LocalRedactionWorker.exe"),
            Path.Combine(root, "dist", "worker", "LocalRedactionWorker.exe"),
            Path.Combine(root, "worker", "LocalRedactionWorker.exe"),
        };

        string? packagedWorker = null;
        foreach (var c in workerCandidates)
            if (File.Exists(c)) { packagedWorker = c; break; }

        var pythonExecutable = Environment.GetEnvironmentVariable("REDACTION_PYTHON_PATH")
            ?? packagedWorker ?? "py";

        HostLog.Info($"Worker executable: {pythonExecutable}");

        string secureToken = Guid.NewGuid().ToString("N");

        PythonWorker worker;
        try { worker = PythonWorker.Start(pythonExecutable, backendPath, secureToken); }
        catch (Exception ex)
        {
            HostLog.Error($"Failed to start worker: {ex}");
            ShowFatal("LocalRedaction couldn't start the background worker.", ex);
            return;
        }

        await using (worker)
        {
            if (!await WaitForHealthAsync(worker.Process, TimeSpan.FromSeconds(20)))
            {
                HostLog.Error("Worker failed health check.");
                ShowFatal("LocalRedaction couldn't start.\n\nThe background worker did not respond in time.", null);
                return;
            }

            var urlBuilder = new UriBuilder("http", "127.0.0.1", WorkerPort)
            { Query = $"token={Uri.EscapeDataString(secureToken)}" };
            string appUrl = urlBuilder.ToString();

            HostLog.Info($"Opening application interface: {appUrl}");
            OpenBrowser(appUrl);

            using var tray = BuildTrayIcon(appUrl);
            Application.Run();
        }
    }

    private static string? FindInstallRoot()
    {
        var env = Environment.GetEnvironmentVariable("REDACTION_INSTALL_ROOT");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env)) return env;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            bool hasBackend = Directory.Exists(Path.Combine(dir.FullName, "backend"));
            bool hasDist = Directory.Exists(Path.Combine(dir.FullName, "dist"));
            bool hasFrontend = Directory.Exists(Path.Combine(dir.FullName, "frontend"));
            if (hasBackend && (hasDist || hasFrontend)) return dir.FullName;
            dir = dir.Parent;
        }
        var guess = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
        if (Directory.Exists(Path.Combine(guess, "backend"))) return guess;
        return null;
    }

    private static NotifyIcon BuildTrayIcon(string appUrl)
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Resources", "app.ico");
        var tray = new NotifyIcon
        {
            Icon = File.Exists(iconPath)
                ? new System.Drawing.Icon(iconPath)
                : System.Drawing.SystemIcons.Application,
            Visible = true,
            Text = "LocalRedaction — running",
        };
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open",      null, (_, _) => OpenBrowser(appUrl));
        menu.Items.Add("Open logs", null, (_, _) => Process.Start("explorer.exe", HostLog.Folder));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quit",      null, (_, _) => Application.Exit());
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (_, _) => OpenBrowser(appUrl);
        tray.BalloonTipTitle = "LocalRedaction is running";
        tray.BalloonTipText  = "Double-click the tray icon to reopen the app.";
        tray.ShowBalloonTip(3000);
        return tray;
    }

    private static void OpenBrowser(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { HostLog.Error($"Failed to open browser: {ex}"); }
    }

    private static void ClearStaleWorkerProcesses(string installRoot)
    {
        var expectedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFullPath(Path.Combine(installRoot, "worker", "LocalRedactionWorker.exe")),
            Path.GetFullPath(Path.Combine(installRoot, "dist", "worker", "LocalRedactionWorker", "LocalRedactionWorker.exe")),
            Path.GetFullPath(Path.Combine(installRoot, "dist", "worker", "LocalRedactionWorker.exe")),
        };

        foreach (var process in Process.GetProcessesByName("LocalRedactionWorker"))
        {
            using (process)
            {
                try
                {
                    var executablePath = process.MainModule?.FileName;
                    if (executablePath is null || !expectedPaths.Contains(Path.GetFullPath(executablePath)))
                        continue;

                    HostLog.Info($"Stopping stale worker process {process.Id} from this installation.");
                    process.Kill(entireProcessTree: true);
                    if (!process.WaitForExit(5000))
                        HostLog.Error($"Stale worker process {process.Id} did not exit in time.");
                }
                catch (Exception ex)
                {
                    HostLog.Error($"Failed to stop stale worker process {process.Id}: {ex.Message}");
                }
            }
        }
    }

    private static async Task<bool> WaitForHealthAsync(Process proc, TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (proc.HasExited) return false;
            try
            {
                using var r = await http.GetAsync(HealthUrl);
                if (r.IsSuccessStatusCode) return true;
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) { }
            await Task.Delay(250);
        }
        return false;
    }

    private static void ShowFatal(string message, Exception? detail)
    {
        var body = detail is null
            ? $"{message}\n\nLogs:\n{HostLog.Folder}"
            : $"{message}\n\n{detail.Message}\n\nLogs:\n{HostLog.Folder}";
        MessageBox.Show(body, "LocalRedaction", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}