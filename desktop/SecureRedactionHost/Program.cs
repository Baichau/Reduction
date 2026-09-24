using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;

public sealed class PythonWorker : IAsyncDisposable
{
    private readonly Process process;

    private PythonWorker(Process process) => this.process = process;

    // ФИКС: Принимаем сгенерированный динамический токен безопасности
    public static PythonWorker Start(string pythonExecutable, string workingDirectory, string secureToken)
    {
        var expectedHash = Environment.GetEnvironmentVariable("REDACTION_WORKER_SHA256");
        if (!string.IsNullOrWhiteSpace(expectedHash) && File.Exists(pythonExecutable))
        {
            var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pythonExecutable)));
            if (!actualHash.Equals(expectedHash.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityException("The configured worker executable hash does not match REDACTION_WORKER_SHA256.");
            }
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = pythonExecutable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,         // ФИКС: Запрещаем создавать новое окно консоли воркера
            WindowStyle = ProcessWindowStyle.Hidden, // ФИКС: Полностью прячем процесс в фон
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        // ФИКС: Безопасно передаем сгенерированный токен воркеру через переменные окружения процесса
        startInfo.Environment["REDACTION_PRODUCTION_TOKEN"] = secureToken;

        var frontendPath = Path.GetFullPath(Path.Combine(workingDirectory, "..", "frontend"));
        if (Directory.Exists(frontendPath))
        {
            startInfo.Environment["REDACTION_FRONTEND_PATH"] = frontendPath;
        }
        startInfo.Environment["REDACTION_DB_PATH"] = Path.Combine(workingDirectory, "data", "redaction.db");
        startInfo.Environment["REDACTION_PROFILES_PATH"] = Path.Combine(workingDirectory, "data", "profiles.json");
        var parserPath = Path.Combine(Path.GetDirectoryName(pythonExecutable) ?? workingDirectory, "LocalRedactionParser.exe");
        if (File.Exists(parserPath))
        {
            startInfo.Environment["REDACTION_PARSER_PATH"] = parserPath;
        }

        if (!Path.GetExtension(pythonExecutable).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.ArgumentList.Add("-m");
            startInfo.ArgumentList.Add("uvicorn");
            startInfo.ArgumentList.Add("app.main:app");
            startInfo.ArgumentList.Add("--host");
            startInfo.ArgumentList.Add("127.0.0.1");
            startInfo.ArgumentList.Add("--port");
            startInfo.ArgumentList.Add("8765");
        }

        var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start Python worker.");
        process.EnableRaisingEvents = true;
        process.Exited += (_, _) => Console.Error.WriteLine($"[worker] exited with code {process.ExitCode}");
        process.OutputDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) Console.WriteLine($"[worker] {eventArgs.Data}"); };
        process.ErrorDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) Console.Error.WriteLine($"[worker] {eventArgs.Data}"); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return new PythonWorker(process);
    }

    public async ValueTask DisposeAsync()
    {
        if (process.HasExited)
        {
            process.Dispose();
            return;
        }

        process.CloseMainWindow();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
        }
        finally
        {
            process.Dispose();
        }
    }
}

public static class Program
{
    public static async Task Main()
    {
        var installRoot = Environment.GetEnvironmentVariable("REDACTION_INSTALL_ROOT")
            ?? (Directory.Exists(Path.Combine(AppContext.BaseDirectory, "backend"))
                ? AppContext.BaseDirectory
                : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..")));
        var backendPath = Path.Combine(installRoot, "backend");
        var packagedWorker = Path.Combine(installRoot, "worker", "LocalRedactionWorker.exe");
        var pythonExecutable = Environment.GetEnvironmentVariable("REDACTION_PYTHON_PATH")
            ?? (File.Exists(packagedWorker) ? packagedWorker : "py");

        string secureToken = Guid.NewGuid().ToString("N");

        await using var worker = PythonWorker.Start(pythonExecutable, backendPath, secureToken);
        Console.WriteLine("Local redaction worker running securely in background.");
        
        string appUrl = $"http://127.0.0.1:8765/?token={Uri.EscapeDataString(secureToken)}";
        Console.WriteLine($"Opening application interface: {appUrl}");
        Process.Start(new ProcessStartInfo(appUrl) { UseShellExecute = true });

        using var shutdown = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            shutdown.Cancel();
        };

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, shutdown.Token);
        }
        catch (OperationCanceledException)
        {
        }
    }
}
