"""封口后 gzip 分块回传。设备原件保留；完整块可复用，未校验块绝不提交。"""
from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

from tracemiku_common import adb_command, atomic_json, make_su_detector, sync_directory

# 272 对齐；只是单块缓冲/重传粒度，不是单文件或采集总量限制。
CHUNK_BYTES = 272 * 65536
COPY_BYTES = 1024 * 1024
MANIFEST_BYTES = 8 * 1024 * 1024
CONTROL_TIMEOUT = 30
TRANSFER_IDLE_SECONDS = 90
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.-]+$")


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(COPY_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def checked_path(path, directory):
    """manifest 的文件必须是已探测 spool 的直接子项。"""
    if not isinstance(path, str) or str(Path(path).parent) != directory:
        raise ValueError("manifest path outside verified spool")
    if not SAFE_NAME.fullmatch(Path(path).name) or Path(path).name in (".", ".."):
        raise ValueError("invalid spool filename")
    return path


class AdbSpool:
    def __init__(self, log=lambda message: None):
        self.log = log
        self.use_su = make_su_detector(log)()

    def shell(self, command, *, timeout=None):
        wrapped = "su -c " + shlex.quote(command) if self.use_su else command
        result = subprocess.run(adb_command("shell", wrapped), capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or
                                f"adb shell exited {result.returncode}").strip()[:1000])
        return result.stdout.strip()

    def read_json(self, path):
        # 限制控制面响应；trace/sidecar 数据走流式文件回传。
        quoted = shlex.quote(path)
        text = self.shell(f"test $(wc -c < {quoted}) -le {MANIFEST_BYTES} && cat {quoted}",
                          timeout=CONTROL_TIMEOUT)
        return json.loads(text)

    def verify_preflight(self, prepared):
        directory = prepared["deviceDir"]
        path = checked_path(prepared["manifestPath"], directory)
        manifest = self.read_json(path)
        if (manifest.get("schema_version") != 1 or manifest.get("state") != "READY" or
                manifest.get("session_id") != prepared["sessionId"] or
                manifest.get("device_dir") != directory or manifest.get("pid") != prepared["pid"]):
            raise ValueError("target-write/root-read preflight identity mismatch")
        self.log(f"设备路径双向探测通过: {directory}")
        return manifest

    def pack_chunk(self, path, session_id, file_id, index, expected, chunk_bytes):
        if not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise ValueError("invalid session id")
        stage = f"/data/local/tmp/.tracemiku-transfer/{session_id}"
        cache_key = hashlib.sha256(f"{path}:{chunk_bytes}".encode()).hexdigest()
        stem = f"{stage}/{cache_key}.{index:08d}"
        source = shlex.quote(path)
        # 只在 SEALED 后执行。每次最多压缩一块；短写/断电残留 .part 不算有效缓存。
        command = f"""set -e
umask 077
mkdir -p {stage}
chmod 711 /data/local/tmp/.tracemiku-transfer
if [ -f {stem}.meta ] && [ -f {stem}.gz ]; then
    read raw_n raw_sha gz_n gz_sha < {stem}.meta || raw_n=invalid
    actual_gzsha=$(sha256sum {stem}.gz)
    actual_rawsha=$(gzip -dc {stem}.gz | sha256sum)
    if [ "$raw_n" != {expected} ] || [ "$gz_n" != "$(wc -c < {stem}.gz)" ] || [ "$gz_sha" != "${{actual_gzsha%% *}}" ] || [ "$raw_sha" != "${{actual_rawsha%% *}}" ] || ! gzip -t {stem}.gz; then
        rm -f {stem}.meta {stem}.gz
    fi
fi
if [ ! -f {stem}.meta ] || [ ! -f {stem}.gz ]; then
    dd if={source} of={stem}.raw.part bs={chunk_bytes} skip={index} count=1 2>/dev/null
    test $(wc -c < {stem}.raw.part) -eq {expected}
    gzip -1 -c {stem}.raw.part > {stem}.gz.part
    gzip -t {stem}.gz.part
    rawsha=$(sha256sum {stem}.raw.part)
    gzsha=$(sha256sum {stem}.gz.part)
    gzsize=$(wc -c < {stem}.gz.part)
    printf '%s %s %s %s\\n' {expected} "${{rawsha%% *}}" "$gzsize" "${{gzsha%% *}}" > {stem}.meta.part
    mv {stem}.gz.part {stem}.gz
    mv {stem}.meta.part {stem}.meta
    rm -f {stem}.raw.part
fi
cat {stem}.meta
"""
        values = self.shell(command).split()
        if (len(values) != 4 or not SHA256.fullmatch(values[1]) or
                not SHA256.fullmatch(values[3])):
            raise ValueError("invalid compressed chunk receipt")
        receipt = {"raw_bytes": int(values[0]), "raw_sha256": values[1],
                   "gzip_bytes": int(values[2]), "gzip_sha256": values[3]}
        if receipt["raw_bytes"] != expected or not 0 < receipt["gzip_bytes"] <= CHUNK_BYTES + 65536:
            raise ValueError("compressed chunk size mismatch")
        # adb pull 以 shell UID 读取独立 staging；私有原件不改权限、不移动。
        self.shell(f"chmod 755 {stage}; chmod 644 {stem}.gz", timeout=CONTROL_TIMEOUT)
        return stem + ".gz", receipt

    def pull_chunk(self, remote, destination, receipt):
        destination = Path(destination)
        if (destination.exists() and destination.stat().st_size == receipt["gzip_bytes"] and
                file_hash(destination) == receipt["gzip_sha256"]):
            return False
        part = destination.with_suffix(destination.suffix + ".part")
        # 仅限制无进展时间；有数据前进的传输没有总时长上限。
        with part.with_suffix(part.suffix + ".log").open("wb") as log:
            process = subprocess.Popen(adb_command("pull", remote, str(part)),
                                       stdout=log, stderr=log, stdin=subprocess.DEVNULL)
            last_size = -1
            last_progress = time.monotonic()
            try:
                while process.poll() is None:
                    size = part.stat().st_size if part.exists() else 0
                    if size != last_size:
                        last_size, last_progress = size, time.monotonic()
                    elif time.monotonic() - last_progress > TRANSFER_IDLE_SECONDS:
                        raise TimeoutError("adb chunk transfer made no progress; rerun recover")
                    time.sleep(0.1)
                if process.returncode:
                    raise RuntimeError(f"adb chunk transfer exited {process.returncode}; rerun recover")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        if part.stat().st_size != receipt["gzip_bytes"] or file_hash(part) != receipt["gzip_sha256"]:
            raise ValueError("compressed chunk checksum mismatch; device source retained")
        with part.open("rb") as verified:
            os.fsync(verified.fileno())
        os.replace(part, destination)
        sync_directory(destination.parent)
        return True

    def export_file(self, artifact, directory, cache, session_id, file_id):
        path = artifact["device_path"]
        size = artifact.get("bytes")
        if type(size) is not int or size < 0:
            raise ValueError("sealed artifact has no valid byte count")
        chunk_bytes = CHUNK_BYTES
        if "record_size" in artifact:
            rec_size = artifact["record_size"]
            if type(rec_size) is not int or not 0 < rec_size <= CHUNK_BYTES:
                raise ValueError("invalid sealed record size")
            if size % rec_size or artifact.get("records") != size // rec_size:
                raise ValueError("sealed record count/byte size mismatch")
            chunk_bytes = CHUNK_BYTES // rec_size * rec_size
        local = Path(directory) / artifact["name"]
        cache = Path(cache) / f"{file_id:04d}"
        cache.mkdir(parents=True, exist_ok=True)
        if int(self.shell(f"wc -c < {shlex.quote(path)}", timeout=CONTROL_TIMEOUT)) != size:
            raise ValueError("device sealed artifact size changed")
        # 原件校验与压缩均在设备封口之后；不依赖被测进程存活。
        digest = self.shell(f"sha256sum {shlex.quote(path)}").split()[0]
        if not SHA256.fullmatch(digest):
            raise ValueError("invalid source SHA-256")
        if local.exists() and local.stat().st_size == size and file_hash(local) == digest:
            return {"name": artifact["name"], "bytes": size, "sha256": digest,
                    "gzip_bytes": 0, "transferred_chunks": 0, "reused_chunks": 0}
        self.log(f"压缩回传 {artifact['name']}: {size:,} bytes")
        part = local.with_suffix(local.suffix + ".part")
        transferred = reused = packed_bytes = 0
        final_hash = hashlib.sha256()
        with part.open("wb") as output:
            for index, offset in enumerate(range(0, size, chunk_bytes)):
                expected = min(chunk_bytes, size - offset)
                receipt_path = cache / f"{index:08d}.json"
                packed = cache / f"{index:08d}.gz"
                receipt = None
                if receipt_path.exists() and packed.exists():
                    try:
                        saved = json.loads(receipt_path.read_text())
                    except (OSError, ValueError):
                        saved = {}
                    if (saved.get("source_sha256") == digest and
                            saved.get("byte_offset") == offset and
                            saved.get("raw_bytes") == expected and
                            packed.stat().st_size == saved.get("gzip_bytes") and
                            file_hash(packed) == saved.get("gzip_sha256")):
                        receipt = saved
                if receipt is None:
                    remote, receipt = self.pack_chunk(path, session_id, file_id, index, expected, chunk_bytes)
                    moved = self.pull_chunk(remote, packed, receipt)
                    receipt["source_sha256"] = digest
                    receipt.update(index=index, byte_offset=offset, name=artifact["name"])
                    if artifact.get("record_size"):
                        receipt.update(record_start=offset // artifact["record_size"],
                                       record_end=(offset + expected) // artifact["record_size"])
                    atomic_json(receipt_path, receipt)
                    transferred += int(moved)
                    reused += int(not moved)
                else:
                    reused += 1
                packed_bytes += receipt["gzip_bytes"]
                raw_hash = hashlib.sha256()
                raw_size = 0
                try:
                    with gzip.open(packed, "rb") as source:
                        while chunk := source.read(COPY_BYTES):
                            raw_size += len(chunk)
                            if raw_size > expected:
                                raise ValueError("gzip expands beyond sealed chunk size")
                            output.write(chunk)
                            raw_hash.update(chunk)
                            final_hash.update(chunk)
                    if raw_size != expected or raw_hash.hexdigest() != receipt["raw_sha256"]:
                        raise ValueError("uncompressed chunk checksum mismatch")
                except (OSError, ValueError, EOFError):
                    receipt_path.unlink(missing_ok=True)
                    raise
                self.log(f"  {artifact['name']}: {offset + expected:,}/{size:,} bytes 已校验")
            output.flush()
            os.fsync(output.fileno())
        if part.stat().st_size != size or final_hash.hexdigest() != digest:
            raise ValueError("complete file SHA-256 mismatch; device source retained")
        os.replace(part, local)
        sync_directory(local.parent)
        return {"name": artifact["name"], "bytes": size, "sha256": digest,
                "gzip_bytes": packed_bytes, "transferred_chunks": transferred, "reused_chunks": reused}


def recover_run(out, rust_json, *, spool=None, log=lambda message: None):
    """从已保存的设备 session 定位封口 manifest；不触发或重跑目标函数。"""
    # 锁文件常驻：unlink 锁文件会允许并发命令锁住另一个 inode 并互相覆盖 .part。
    with (Path(out) / ".recovery.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("这个 run 已有恢复任务运行；等待其结束后再执行 recover") from None
        return _recover_run(out, rust_json, spool=spool, log=log)


def _recover_run(out, rust_json, *, spool, log):
    out = Path(out).resolve()
    recovery = json.loads((out / "recovery.json").read_text())
    if recovery.get("schema_version") != 1:
        raise ValueError("unsupported recovery descriptor")
    if recovery.get("serial") and os.environ.get("ANDROID_SERIAL") not in (None, recovery["serial"]):
        raise ValueError("ANDROID_SERIAL differs from capture device")
    if recovery.get("serial"):
        os.environ["ANDROID_SERIAL"] = recovery["serial"]
    spool = spool or AdbSpool(log)
    results = []
    pending = []
    acknowledgements = []
    for source in recovery["sessions"]:
        device_dir = source["deviceDir"]
        session = spool.read_json(checked_path(source["manifestPath"], device_dir))
        if session.get("session_id") != source["sessionId"] or session.get("schema_version") != 1:
            raise ValueError("device session identity changed")
        if session.get("state") != "SEALED" or not session.get("calls"):
            item = {"session_id": source["sessionId"], "state": session.get("state", "UNKNOWN")}
            if session.get("error"):
                item["error"] = str(session["error"])[:1000]
            pending.append(item)
            continue
        for manifest_path in session.get("calls", []):
            manifest = spool.read_json(checked_path(manifest_path, device_dir))
            if manifest.get("session_id") != source["sessionId"] or manifest.get("schema_version") != 1:
                raise ValueError("call manifest identity changed")
            if manifest.get("state") != "SEALED":
                pending.append({"manifest": manifest_path, "state": manifest.get("state", "UNKNOWN")})
                continue
            meta = manifest["meta"]
            call_idx, tid = meta["callIdx"], meta["tid"]
            if type(call_idx) is not int or call_idx < 1 or type(tid) is not int or tid < 1:
                raise ValueError("invalid call identity")
            names = set()
            artifacts = []
            for artifact in manifest["files"]:
                name = artifact["name"]
                if not SAFE_NAME.fullmatch(name) or name in (".", "..", "meta.json") or name in names:
                    raise ValueError("invalid/duplicate artifact name")
                names.add(name)
                checked_path(artifact["device_path"], device_dir)
                artifacts.append(artifact)
            if "trace.bin" not in names:
                raise ValueError("sealed manifest has no trace.bin")
            committed = None
            for directory in (out / "calls").glob(f"call_{call_idx:03d}_tid{tid}_*"):
                existing = json.loads((directory / "meta.json").read_text())
                if existing.get("session_id") != source["sessionId"]:
                    continue
                receipts = existing.get("artifact_checksums", [])
                expected_names = names
                if (existing.get("transfer_state") == "VERIFIED" and
                        {item["name"] for item in receipts} == expected_names and
                        all((directory / item["name"]).is_file() and
                            (directory / item["name"]).stat().st_size == item["bytes"] and
                            file_hash(directory / item["name"]) == item["sha256"]
                            for item in receipts)):
                    committed = {"call_idx": call_idx, "tid": tid, "records": existing["records"],
                                 "bytes": existing["bytes"], "truncated": existing.get("truncated", True),
                                 "artifacts": receipts, "path": str(directory)}
                    break
                raise ValueError("已提交目录的校验失败；保留现场，请用新目录恢复设备源")
            if committed:
                results.append(committed)
                continue
            # call 的目录编号不从 host 消息推断；按设备事实构造暂存目录。
            pending_dir = out / "calls" / f"_pending_call_{call_idx:03d}"
            pending_dir.mkdir(parents=True, exist_ok=True)
            meta = {**meta, "device_manifest": manifest_path, "session_id": source["sessionId"],
                    "transfer_state": "PENDING", "required_artifacts": sorted(names)}
            atomic_json(pending_dir / "meta.json", meta)
            receipts = []
            try:
                cache = out / ".transfer" / source["sessionId"] / f"call_{call_idx:03d}"
                for file_id, artifact in enumerate(artifacts):
                    receipts.append(spool.export_file(artifact, pending_dir, cache, source["sessionId"], file_id))
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                meta["transfer_error"] = str(error)[:1000]
                atomic_json(pending_dir / "meta.json", meta)
                pending.append({"manifest": manifest_path, "state": "TRANSFER_PENDING", "error": str(error)[:1000]})
                continue
            meta["transfer_state"] = "VERIFIED"
            meta["artifact_checksums"] = receipts
            atomic_json(pending_dir / "meta.json", meta)
            # 派生字段/目录收尾由 core 完成，host 不解码指令或修补分析语义。
            results.append({"call_idx": call_idx, "tid": tid, "records": meta["records"],
                            "bytes": meta["bytes"], "truncated": meta.get("truncated", True),
                            "artifacts": receipts, "path": str(pending_dir)})
            # ACK 只是校验凭据；原件仍保留，便于复核和再次恢复。
            ack = json.dumps({"session_id": source["sessionId"], "call_idx": call_idx,
                              "artifacts": receipts}, separators=(",", ":"))
            ack_path = shlex.quote(device_dir + f"/call_{call_idx}.verified.json")
            acknowledgements.append((ack_path, ack))
    final = rust_json(["finalize", str(out)])
    for call in results:
        renamed = next((item["to"] for item in final["calls"]
                        if item["from"] == Path(call["path"]).name), None)
        if renamed:
            call["path"] = str(out / "calls" / renamed)
        # 完成度由 core 的 info 语义判定；回传成功不等于采集没有缺口。
        call["is_complete"] = rust_json(["info", call["path"]])["is_complete"]
    if final.get("pending", 0) and not pending:
        pending.append({"state": "LOCAL_PENDING", "error": "core 校验未通过，保留 pending"})
    for path, ack in acknowledgements:
        spool.shell(f"printf %s {shlex.quote(ack)} > {path}", timeout=CONTROL_TIMEOUT)
    status = "pending" if pending else "incomplete" if any(not call["is_complete"] for call in results) else "ok"
    result = {"schema_version": 1, "status": status, "out": str(out), "calls": results, "pending": pending, "error": None}
    atomic_json(out / "recovery-result.json", result)
    return result
