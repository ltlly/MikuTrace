"""压缩块的恢复与校验契约；使用真实 gzip/文件，ADB 仅替换为本机 copy。"""
import fcntl
import gzip
import hashlib
import json
import shlex
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tracemiku_spool as spool_module
from tracemiku_spool import AdbSpool, checked_path


class LocalSpool(AdbSpool):
    def __init__(self, staging):
        self.log = lambda message: None
        self.staging = staging
        self.packs = []
        self.fail_index = None

    def shell(self, command, **kwargs):
        tokens = shlex.split(command)
        if tokens[0] == "sha256sum":
            return hashlib.sha256(Path(tokens[1]).read_bytes()).hexdigest() + "  source"
        if tokens[0] == "wc":
            return str(Path(tokens[-1]).stat().st_size)
        raise AssertionError(command)

    def pack_chunk(self, path, session_id, file_id, index, expected, chunk_bytes):
        self.packs.append(index)
        if index == self.fail_index:
            raise ConnectionError("USB disconnected")
        with Path(path).open("rb") as source:
            source.seek(index * chunk_bytes)
            raw = source.read(expected)
        packed = gzip.compress(raw, mtime=0)
        file = self.staging / f"{file_id}.{index}.gz"
        file.write_bytes(packed)
        return str(file), {
            "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "gzip_bytes": len(packed), "gzip_sha256": hashlib.sha256(packed).hexdigest(),
        }


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setattr(spool_module, "CHUNK_BYTES", 272 * 3)
    monkeypatch.setattr(spool_module, "adb_command", lambda op, source, dest: ["cp", source, dest])
    device = tmp_path / "device"
    device.mkdir()
    target = tmp_path / "call"
    target.mkdir()
    cache = tmp_path / "cache"
    contents = bytes((index * 71 + index // 7) % 256 for index in range(272 * 10))
    source = device / "trace.bin"
    source.write_bytes(contents)
    artifact = {"name": "trace.bin", "device_path": str(source), "bytes": len(contents),
                "record_size": 272, "records": 10}
    return LocalSpool(device), artifact, contents, target, cache


def test_disconnect_reuses_verified_chunks_without_recapturing(local):
    spool, artifact, contents, target, cache = local
    spool.fail_index = 2
    with pytest.raises(ConnectionError):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert not (target / "trace.bin").exists(), "部分文件不能成为已提交 trace.bin"
    assert len(list(cache.rglob("*.json"))) == 2
    assert Path(artifact["device_path"]).read_bytes() == contents
    spool.fail_index = None
    spool.packs.clear()
    result = spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert result["reused_chunks"] == 2
    assert result["transferred_chunks"] == 2
    assert spool.packs == [2, 3]
    assert (target / "trace.bin").read_bytes() == contents
    assert result["sha256"] == hashlib.sha256(contents).hexdigest()
    assert Path(artifact["device_path"]).read_bytes() == contents


def test_bad_cached_gzip_is_retransmitted_and_existing_final_is_not_destroyed(local):
    spool, artifact, contents, target, cache = local
    spool.fail_index = 1
    (target / "trace.bin").write_bytes(b"previous data")
    with pytest.raises(ConnectionError):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert (target / "trace.bin").read_bytes() == b"previous data"
    next(cache.rglob("*.gz")).write_bytes(b"broken")
    spool.fail_index = None
    spool.packs.clear()
    spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert spool.packs == [0, 1, 2, 3]
    assert (target / "trace.bin").read_bytes() == contents


def test_record_count_mismatch_fails_before_transfer(local):
    spool, artifact, _, target, cache = local
    artifact["records"] = 11
    with pytest.raises(ValueError, match="record count"):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert spool.packs == []


def test_concurrent_recovery_cannot_overwrite_in_progress_files(tmp_path):
    with (tmp_path / ".recovery.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="已有恢复任务"):
            spool_module.recover_run(tmp_path, None)


def test_simd_chunks_preserve_whole_records_and_exact_record_ranges(local):
    spool, artifact, _, target, cache = local
    data = bytes(range(256)) * 20 + b"x" * 80
    assert len(data) == 520 * 10
    Path(artifact["device_path"]).write_bytes(data)
    artifact.update(name="simd_trace.bin", bytes=len(data), record_size=520, records=10)
    spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert (target / "simd_trace.bin").read_bytes() == data
    receipts = [json.loads(path.read_text()) for path in sorted(cache.rglob("*.json"))]
    assert [(r["record_start"], r["record_end"], r["byte_offset"], r["raw_bytes"]) for r in receipts] == [
        (i, i + 1, i * 520, 520) for i in range(10)]


def test_corrupt_cached_raw_receipt_is_invalidated_for_next_recovery(local):
    spool, artifact, contents, target, cache = local
    spool.fail_index = 1
    with pytest.raises(ConnectionError):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    path = next(cache.rglob("*.json"))
    receipt = json.loads(path.read_text())
    receipt["raw_sha256"] = "0" * 64
    path.write_text(json.dumps(receipt))
    spool.fail_index = None
    with pytest.raises(ValueError, match="checksum"):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert not path.exists()
    spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert (target / "trace.bin").read_bytes() == contents


@pytest.mark.parametrize("path", ["/private/secret", "/spool/../secret", "/spool/sub/trace.bin"])
def test_manifest_never_changes_transfer_source_directory(path):
    with pytest.raises(ValueError):
        checked_path(path, "/spool")


def test_corrupt_source_cannot_be_committed_with_old_checksum(local):
    spool, artifact, _, target, cache = local
    original = spool.pack_chunk
    def tamper(*args):
        remote, receipt = original(*args)
        receipt["raw_sha256"] = "0" * 64
        return remote, receipt
    spool.pack_chunk = tamper
    with pytest.raises(ValueError, match="checksum"):
        spool.export_file(artifact, target, cache, "a" * 32, 0)
    assert not (target / "trace.bin").exists()


def test_root_command_is_one_quoted_remote_argument(monkeypatch):
    from types import SimpleNamespace
    seen = []
    spool = AdbSpool.__new__(AdbSpool)
    spool.use_su = True
    command = "cat '/private/path with spaces/manifest.json' && id"
    monkeypatch.setattr(spool_module.subprocess, "run", lambda argv, **kwargs: (
        seen.append(argv) or SimpleNamespace(returncode=0, stdout="ok", stderr="")))
    spool.shell(command)
    assert shlex.split(seen[0][-1]) == ["su", "-c", command]
    assert seen[0][-2] == "shell"


def test_preflight_checks_actual_session_identity(monkeypatch):
    spool = AdbSpool.__new__(AdbSpool)
    spool.log = lambda message: None
    monkeypatch.setattr(spool, "read_json", lambda path: {
        "schema_version": 1, "state": "READY", "session_id": "wrong", "pid": 7, "device_dir": "/private"})
    with pytest.raises(ValueError, match="identity"):
        spool.verify_preflight({"deviceDir": "/private", "manifestPath": "/private/session.json",
                                "sessionId": "a" * 32, "pid": 7})


def test_recovery_sidecar_failure_remains_pending_and_does_not_ack(tmp_path, monkeypatch):
    out = tmp_path / "run"
    out.mkdir()
    (out / "calls").mkdir()
    source = {"deviceDir": "/spool", "manifestPath": "/spool/session.json",
              "sessionId": "a" * 32, "pid": 7}
    (out / "recovery.json").write_text(json.dumps({"schema_version": 1, "serial": None, "sessions": [source]}))
    class Incomplete:
        def read_json(self, path):
            if path.endswith("session.json"):
                return {"schema_version": 1, "session_id": "a" * 32, "state": "SEALED", "calls": ["/spool/call_1.json"]}
            return {"schema_version": 1, "session_id": "a" * 32, "state": "SEALED",
                    "meta": {"callIdx": 1, "tid": 7, "records": 1, "bytes": 272},
                    "files": [{"name": name, "device_path": "/spool/" + name} for name in ("trace.bin", "simd_trace.bin")]}
        def export_file(self, artifact, destination, *args):
            if artifact["name"] == "simd_trace.bin":
                raise ConnectionError("disconnected")
            (destination / "trace.bin").write_bytes(b"a" * 272)
            return {"name": "trace.bin", "bytes": 272, "sha256": "a" * 64}
        def shell(self, *args, **kwargs):
            raise AssertionError("incomplete result must not be ACKed")
    result = spool_module.recover_run(out, lambda args: {"calls": [], "pending": 1}, spool=Incomplete())
    assert result["status"] == "pending"
    meta = json.loads((out / "calls/_pending_call_001/meta.json").read_text())
    assert meta["transfer_state"] == "PENDING"
    assert "simd_trace.bin" in meta["required_artifacts"]
    assert result["calls"] == []
