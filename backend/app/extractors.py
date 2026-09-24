import csv
import io
import json
from pathlib import Path

import base64
import subprocess
import os
import sys
import time
import zipfile
import psutil


class UnsupportedFileType(ValueError):
    pass


class FileExtractionError(ValueError):
    pass


MAX_EXTRACTED_CHARS = 2_000_000
PARSER_TIMEOUT_SECONDS = 15
PARSER_MEMORY_BYTES = 256 * 1024 * 1024


def _ensure_output(text: str) -> str:
    if len(text) > MAX_EXTRACTED_CHARS:
        raise FileExtractionError("Extracted text exceeds the 2 MB processing limit")
    return text


def extract_text_in_process(filename: str, content: bytes) -> tuple[str, str]:
    suffix = Path(filename).suffix.lower()
    if suffix in {".txt", ".md", ".log", ".eml"}:
        return _ensure_output(content.decode("utf-8-sig", errors="replace")), "text"
    if suffix == ".csv":
        rows = csv.reader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
        return _ensure_output("\n".join(" | ".join(row) for row in rows)), "csv"
    if suffix == ".json":
        try:
            value = json.loads(content.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FileExtractionError("The JSON file could not be parsed") from error
        return _ensure_output(json.dumps(value, indent=2, ensure_ascii=False)), "json"
    if suffix == ".pdf":
        from pypdf import PdfReader
        try:
            reader = PdfReader(io.BytesIO(content), strict=False)
            text = "\n\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as error:
            raise FileExtractionError("The PDF file could not be parsed") from error
        return _ensure_output(text), "pdf"
    if suffix == ".docx":
        if not zipfile.is_zipfile(io.BytesIO(content)):
            raise FileExtractionError("The DOCX container is invalid")
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            if "word/vbaProject.bin" in names or any("externalLink" in name for name in names):
                raise FileExtractionError("DOCX macros and external links are not supported")
        from docx import Document
        try:
            document = Document(io.BytesIO(content))
        except Exception as error:
            raise FileExtractionError("The DOCX file could not be parsed") from error
        return _ensure_output("\n".join(paragraph.text for paragraph in document.paragraphs)), "docx"
    raise UnsupportedFileType(f"Unsupported file type: {suffix or 'unknown'}")


def extract_text(filename: str, content: bytes) -> tuple[str, str]:
    request = json.dumps({"filename": filename, "content": base64.b64encode(content).decode("ascii")})
    environment = {
        key: os.environ[key]
        for key in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    parser_executable = os.getenv("REDACTION_PARSER_PATH")
    command = [parser_executable] if parser_executable else [sys.executable, "-m", "app.parser_worker"]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        started = time.monotonic()
        process.stdin.write(request)
        process.stdin.close()
        while process.poll() is None:
            if time.monotonic() - started > PARSER_TIMEOUT_SECONDS:
                raise FileExtractionError("Parser exceeded the 15 second timeout")
            try:
                if psutil.Process(process.pid).memory_info().rss > PARSER_MEMORY_BYTES:
                    raise FileExtractionError("Parser exceeded the 256 MB memory limit")
            except psutil.NoSuchProcess:
                break
            time.sleep(0.02)
        process.wait()
        stdout = process.stdout.read()
        if process.returncode != 0:
            raise FileExtractionError("The isolated parser rejected the file")
        try:
            result = json.loads(stdout)
            return _ensure_output(result["text"]), result["source_type"]
        except (json.JSONDecodeError, KeyError) as error:
            raise FileExtractionError("The isolated parser returned an invalid response") from error
    except (BrokenPipeError, TimeoutError):
        raise FileExtractionError("The isolated parser failed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
