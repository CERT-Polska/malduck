import json
import os
import tempfile

import pytest
from click.testing import CliRunner

from malduck.main import main


@pytest.fixture
def runner():
    return CliRunner()


def make_script(tmpdir, body):
    """Write a Python script to a temporary file and return its path."""
    path = os.path.join(tmpdir, "script.py")
    with open(path, "w") as f:
        f.write(body)
    return path


def test_execute_basic(runner):
    """execute command runs a script against a file and outputs JSON."""
    with runner.isolated_filesystem():
        # Create a small binary file
        with open("sample.bin", "wb") as f:
            f.write(b"\x00" * 16)

        # Create a script that returns file length
        with open("script.py", "w") as f:
            f.write("def run(p):\n    return {'length': p.length}\n")

        result = runner.invoke(main, ["execute", "script.py", "sample.bin"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data == {"length": 16}


def test_execute_returns_none(runner):
    """execute command produces no output when run() returns None."""
    with runner.isolated_filesystem():
        with open("sample.bin", "wb") as f:
            f.write(b"hello world")

        with open("script.py", "w") as f:
            f.write("def run(p):\n    return None\n")

        result = runner.invoke(main, ["execute", "script.py", "sample.bin"])
        assert result.exit_code == 0
        assert result.output.strip() == ""


def test_execute_multiple_files(runner):
    """execute command iterates over multiple files."""
    with runner.isolated_filesystem():
        for name, size in [("a.bin", 4), ("b.bin", 8)]:
            with open(name, "wb") as f:
                f.write(b"\x00" * size)

        with open("script.py", "w") as f:
            f.write("def run(p):\n    return {'length': p.length}\n")

        result = runner.invoke(main, ["execute", "script.py", "a.bin", "b.bin"])
        assert result.exit_code == 0
        # Each JSON object is emitted on multiple lines; collect by parsing streamed objects
        outputs = []
        decoder = json.JSONDecoder()
        text = result.output
        idx = 0
        while idx < len(text):
            text_slice = text[idx:].lstrip()
            if not text_slice:
                break
            idx_offset = len(text[idx:]) - len(text_slice)
            try:
                obj, end = decoder.raw_decode(text_slice)
                outputs.append(obj)
                idx += idx_offset + end
            except json.JSONDecodeError:
                break
        assert len(outputs) == 2
        assert outputs[0]["length"] == 4
        assert outputs[1]["length"] == 8


def test_execute_directory(runner):
    """execute command processes all files in a directory."""
    with runner.isolated_filesystem():
        os.makedirs("dumps")
        for name, size in [("x.bin", 2), ("y.bin", 3)]:
            with open(os.path.join("dumps", name), "wb") as f:
                f.write(b"\x00" * size)

        with open("script.py", "w") as f:
            f.write("def run(p):\n    return {'length': p.length}\n")

        result = runner.invoke(main, ["execute", "script.py", "dumps"])
        assert result.exit_code == 0
        outputs = []
        decoder = json.JSONDecoder()
        text = result.output
        idx = 0
        while idx < len(text):
            text_slice = text[idx:].lstrip()
            if not text_slice:
                break
            idx_offset = len(text[idx:]) - len(text_slice)
            try:
                obj, end = decoder.raw_decode(text_slice)
                outputs.append(obj)
                idx += idx_offset + end
            except json.JSONDecodeError:
                break
        assert len(outputs) == 2
        sizes = sorted(o["length"] for o in outputs)
        assert sizes == [2, 3]


def test_execute_missing_run_function(runner):
    """execute command raises an error when the script has no run() function."""
    with runner.isolated_filesystem():
        with open("sample.bin", "wb") as f:
            f.write(b"data")

        with open("script.py", "w") as f:
            f.write("# no run function here\n")

        result = runner.invoke(main, ["execute", "script.py", "sample.bin"])
        assert result.exit_code != 0
        assert "run" in result.output.lower() or "run" in (result.exception and str(result.exception) or "")


def test_execute_with_base_address(runner):
    """execute command passes base address to ProcessMemory."""
    with runner.isolated_filesystem():
        with open("sample.bin", "wb") as f:
            f.write(b"\x00" * 8)

        with open("script.py", "w") as f:
            f.write("def run(p):\n    return {'base': p.imgbase}\n")

        result = runner.invoke(
            main, ["execute", "--base", "0x400000", "script.py", "sample.bin"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["base"] == 0x400000


def test_execute_script_reads_memory(runner):
    """execute command script can access file content via ProcessMemory."""
    with runner.isolated_filesystem():
        with open("sample.bin", "wb") as f:
            f.write(b"HELLO")

        with open("script.py", "w") as f:
            f.write(
                "def run(p):\n"
                "    data = p.readp(0, 5)\n"
                "    return {'first_bytes': list(data)}\n"
            )

        result = runner.invoke(main, ["execute", "script.py", "sample.bin"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["first_bytes"] == list(b"HELLO")
