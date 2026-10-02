using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SecureRedactionHost;

internal sealed class PythonWorker : IAsyncDisposable
{
    private readonly Process process;

    public Process Process => process;

    private PythonWorker(Process process) => this.process = process;

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
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        startInfo.Environment["REDACTION_PRODUCTION_TOKEN"] = secureToken;

        var frontendPath = Path.GetFullPath(Path.Combine(workingDirectory, "..", "frontend"));
        if (Directory.Exists(frontendPath))
        {
            startInfo.Environment["REDACTION_FRONTEND_PATH"] = frontendPath;
        }

        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalRedaction");
        Directory.CreateDirectory(dataDirectory);

        startInfo.Environment["REDACTION_ENV"] = "production";
        startInfo.Environment["REDACTION_DATA_DIR"] = dataDirectory;
        startInfo.Environment["REDACTION_DB_PATH"] = Path.Combine(dataDirectory, "redaction.db");
        startInfo.Environment["REDACTION_PROFILES_PATH"] = Path.Combine(dataDirectory, "profiles.json");

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

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start Python worker.");

        process.EnableRaisingEvents = true;
        process.Exited += (_, _) =>
            HostLog.Error($"[worker] exited with code {process.ExitCode}");

        process.OutputDataReceived += (_, e) =>
            { if (e.Data is not null) HostLog.Info($"[worker] {e.Data}"); };

        process.ErrorDataReceived += (_, e) =>
            { if (e.Data is not null) HostLog.Error($"[worker] {e.Data}"); };

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