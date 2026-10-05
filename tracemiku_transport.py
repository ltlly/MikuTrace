"""有界、host 驱动的 Frida 二进制回传；不执行任何设备 shell 命令。"""

import os
import pathlib
import queue
import threading
import time
import uuid

MAX_BYTES = 8 * 1024**3
CHUNK_BYTES = 256 * 1024
TIMEOUT = 180


class FridaTransport:
    """窗口固定为 1：收到并写完一块，才请求下一块。

    message 回调只投递到容量 1 的邮箱，不做 RPC、不写磁盘。
    超时/断线保留设备 spool，删除本次 .part，不替换已有目标文件。
    每个 Script 实例独立一个 transport；一次仅允许一个 transfer。
    """

    def __init__(self, script, *, max_bytes=MAX_BYTES, chunk_bytes=CHUNK_BYTES,
                 timeout=TIMEOUT):
        if not 1 <= max_bytes <= MAX_BYTES:
            raise ValueError("max_bytes 必须在 1..8GiB")
        if not 4096 <= chunk_bytes <= CHUNK_BYTES:
            raise ValueError("chunk_bytes 必须在 4096..262144")
        if not 1 <= timeout <= 900:
            raise ValueError("timeout 必须在 1..900 秒")
        self.script = script
        self.max_bytes = max_bytes
        self.chunk_bytes = chunk_bytes
        self.timeout = timeout
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._active = None

    def on_message(self, message, data):
        payload = message.get("payload")
        if message.get("type") != "send" or not isinstance(payload, dict):
            return False
        if payload.get("type") != "spool-response":
            return False
        with self._state_lock:
            active = self._active
            if active is not None and payload.get("id") == active[0]:
                # 每次请求只有一个响应；满邮箱意味着协议错误，不能无限排队。
                if data is not None and len(data) > self.chunk_bytes:
                    payload = {"error": "响应超过 chunk 预算"}
                    data = None
                try:
                    active[1].put_nowait((payload, data))
                except queue.Full:
                    active[2].set()
        return True

    def pull(self, device_path, dst_path, *, expect_bytes=None, record_size=None):
        if expect_bytes is not None and (
                type(expect_bytes) is not int or not 0 <= expect_bytes <= self.max_bytes):
            raise ValueError("expect_bytes 超过传输预算或类型无效")
        if record_size is not None and (type(record_size) is not int or record_size < 1):
            raise ValueError("record_size 必须是正整数")
        dst = pathlib.Path(dst_path)
        part = pathlib.Path(str(dst) + ".part")
        with self._lock:
            transfer_id = uuid.uuid4().hex
            mailbox = queue.Queue(maxsize=1)
            overflow = threading.Event()
            with self._state_lock:
                self._active = (transfer_id, mailbox, overflow)
            deadline = time.monotonic() + self.timeout

            def request(op, **fields):
                self.script.post({"type": "spool-request", "payload": {
                    "id": transfer_id, "op": op, **fields,
                }})
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Frida spool 回传总时限已到")
                try:
                    payload, binary = mailbox.get(timeout=remaining)
                except queue.Empty:
                    raise TimeoutError("Frida spool 响应超时；设备源文件保留") from None
                if overflow.is_set():
                    raise RuntimeError("Frida spool 响应窗口溢出")
                if payload.get("error"):
                    raise RuntimeError(str(payload["error"])[:500])
                if payload.get("op") != op:
                    raise RuntimeError("Frida spool 响应 op 不匹配")
                return payload, binary

            try:
                manifest, binary = request("open", path=str(device_path),
                                           maxBytes=self.max_bytes)
                size = manifest.get("size")
                if type(size) is not int or not 0 <= size <= self.max_bytes or binary:
                    raise RuntimeError("Frida spool manifest 无效或超预算")
                if expect_bytes is not None and size != expect_bytes:
                    raise RuntimeError(f"spool 字节数不匹配: {size} != {expect_bytes}")
                if record_size and size % record_size:
                    raise RuntimeError("spool 字节数不是 record_size 的整倍数")
                # xb 不覆盖其它失败会话留下的临时文件。
                with part.open("xb") as fp:
                    offset = 0
                    while offset < size:
                        want = min(self.chunk_bytes, size - offset)
                        response, data = request("read", offset=offset, count=want)
                        if response.get("offset") != offset or data is None or len(data) != want:
                            raise RuntimeError("Frida spool 块偏移或长度不匹配")
                        fp.write(data)
                        offset += want
                    fp.flush()
                    os.fsync(fp.fileno())
                request("close")  # 关闭设备句柄成功后才提交；源文件永不删除。
                os.replace(part, dst)
                return size
            except BaseException:
                # .part 已存在时不能误删别的事务留下的文件。
                if 'fp' in locals():
                    part.unlink(missing_ok=True)
                try:
                    self.script.post({"type": "spool-request", "payload": {
                        "id": transfer_id, "op": "cancel",
                    }})
                except Exception:
                    pass
                raise
            finally:
                with self._state_lock:
                    self._active = None
