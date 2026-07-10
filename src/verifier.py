"""
Phase 2: 双重 TLS 交叉验证 + Phase 3 冗余检测
高并发 asyncio + Semaphore，任意一步失败即丢弃。
支持重试、代理、进度显示。
"""

import asyncio
import logging
import random
import string
import ssl
import sys
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .exceptions import ConnectionError as XiaoConnError, TLSHandshakeError, CertParseError, CFVerifyError

logger = logging.getLogger("xiao.verifier")


async def _open_connection(ip: str, port: int, timeout: float, proxy_url: str | None = None):
    """建立 TCP 连接，支持 SOCKS5/HTTP 代理"""
    if proxy_url:
        return await _open_connection_via_proxy(ip, port, timeout, proxy_url)
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port), timeout=timeout
    )


async def _open_connection_via_proxy(ip: str, port: int, timeout: float, proxy_url: str):
    """通过 SOCKS5/HTTP 代理建立连接"""
    try:
        from python_socks.async_.asyncio import Proxy
        from python_socks import ProxyType, parse_proxy_url
    except ImportError:
        logger.warning("代理需要 python-socks 库: pip install python-socks[asyncio]")
        raise XiaoConnError("python-socks 未安装")

    proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass = parse_proxy_url(proxy_url)
    proxy = Proxy(
        proxy_type=proxy_type,
        host=proxy_host,
        port=proxy_port,
        username=proxy_user,
        password=proxy_pass,
    )
    sock = await asyncio.wait_for(
        proxy.connect(dest_host=ip, dest_port=port), timeout=timeout
    )
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer


async def verify_single(
    ip: str,
    port: int,
    target_sni: str,
    my_cf_domain: str,
    timeout: float = 3.0,
    redundancy_check: bool = True,
    retries: int = 1,
    proxy_url: str | None = None,
) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for attempt in range(retries):
        if attempt > 0:
            await asyncio.sleep(min(2 ** (attempt - 1), 8))

        result = await _attempt_verify(
            ip, port, target_sni, my_cf_domain, ctx, timeout, redundancy_check, proxy_url
        )
        if result is not None:
            return result

        if attempt < retries - 1:
            logger.debug(f"重试 {ip}:{port} (第 {attempt + 2}/{retries} 次)")

    return None


async def _attempt_verify(
    ip: str,
    port: int,
    target_sni: str,
    my_cf_domain: str,
    ctx: ssl.SSLContext,
    timeout: float,
    redundancy_check: bool,
    proxy_url: str | None,
) -> dict | None:
    # ── Step 1: REALITY 身份实锤 ──
    try:
        reader, writer = await _open_connection(ip, port, timeout, proxy_url)
    except Exception:
        return None

    try:
        loop = asyncio.get_running_loop()
        ssl_obj = await loop.start_tls(
            writer.transport,
            protocol_factory=None,
            sslcontext=ctx,
            server_hostname=target_sni,
        )
        if ssl_obj is None:
            return None
        der_cert = ssl_obj.get_extra_info("peercert", binary_form=True)
    except Exception:
        der_cert = None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not der_cert:
        return None

    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cns:
            return None
        common_name = cns[0].value
    except Exception:
        return None

    if target_sni.lower() not in str(common_name).lower():
        return None

    # ── Step 2: CF 反代配置特性判定 ──
    try:
        reader, writer = await _open_connection(ip, port, timeout, proxy_url)
    except Exception:
        return None

    try:
        loop = asyncio.get_running_loop()
        await loop.start_tls(
            writer.transport,
            protocol_factory=None,
            sslcontext=ctx,
            server_hostname=my_cf_domain,
        )
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {my_cf_domain}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        res_text = response.decode("utf-8", errors="ignore").lower()
    except Exception:
        res_text = ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if "server: cloudflare" not in res_text and "cf-ray" not in res_text:
        return None

    # ── Phase 3: 冗余检测 ──
    if redundancy_check and await _is_redundancy(ip, port, timeout, proxy_url):
        logger.debug(f"冗余检测阳性: {ip}:{port}")
        return None

    return {
        "ip": ip,
        "port": port,
        "target_sni": target_sni,
        "common_name": str(common_name),
        "status": "AVAILABLE",
    }


async def _is_redundancy(ip: str, port: int, timeout: float, proxy_url: str | None = None) -> bool:
    random_sni = "".join(random.choices(string.ascii_lowercase, k=10)) + ".org"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await _open_connection(ip, port, timeout, proxy_url)
        loop = asyncio.get_running_loop()
        await loop.start_tls(
            writer.transport,
            protocol_factory=None,
            sslcontext=ctx,
            server_hostname=random_sni,
        )
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {random_sni}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(512), timeout=timeout)
        res_text = response.decode("utf-8", errors="ignore").lower()
        writer.close()
        await writer.wait_closed()
        if "server: cloudflare" in res_text or "cf-ray" in res_text:
            return True
    except Exception:
        pass
    return False


async def verify_batch(
    targets: list[tuple[str, int]],
    target_snis: list[str],
    my_cf_domain: str,
    concurrency: int = 500,
    timeout: float = 3.0,
    redundancy_check: bool = True,
    retries: int = 1,
    proxy_url: str | None = None,
    shutdown_event: asyncio.Event | None = None,
    progress: bool = True,
):
    sem = asyncio.Semaphore(concurrency)
    task_queue: asyncio.Queue = asyncio.Queue()
    result_queue: asyncio.Queue = asyncio.Queue()

    for ip, port in targets:
        for sni in target_snis:
            await task_queue.put((ip, port, sni))

    total = task_queue.qsize()
    completed = 0
    found = 0
    start_time = time.monotonic()
    progress_lock = asyncio.Lock()

    if progress and total > 0:
        _print_progress(completed, total, found, 0, start_time)

    async def worker():
        nonlocal completed, found
        while True:
            if shutdown_event and shutdown_event.is_set():
                return
            try:
                ip, port, sni = task_queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            async with sem:
                result = await verify_single(
                    ip, port, sni, my_cf_domain,
                    timeout=timeout,
                    redundancy_check=redundancy_check,
                    retries=retries,
                    proxy_url=proxy_url,
                )
                if result:
                    await result_queue.put(result)
                    found += 1
                completed += 1
                if progress and total > 0:
                    async with progress_lock:
                        elapsed = time.monotonic() - start_time
                        _print_progress(completed, total, found, elapsed, start_time)
                task_queue.task_done()

    worker_count = min(concurrency, total)
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await asyncio.gather(*workers, return_exceptions=True)

    if progress and total > 0:
        elapsed = time.monotonic() - start_time
        _print_progress(total, total, found, elapsed, start_time, final=True)

    while not result_queue.empty():
        yield await result_queue.get()


def _print_progress(completed: int, total: int, found: int, elapsed: float, start_time: float, final: bool = False):
    pct = completed / total * 100 if total > 0 else 0
    bar_width = 30
    filled = int(bar_width * completed / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_width - filled)

    if completed > 0 and elapsed > 0:
        rate = completed / elapsed
        eta = (total - completed) / rate if rate > 0 else 0
        eta_str = f"ETA {eta:.0f}s" if not final else ""
    else:
        eta_str = ""

    line = (
        f"\r  [{bar}] {pct:5.1f}%  "
        f"{completed}/{total}  "
        f"[+] {found}  "
        f"{eta_str}"
    )
    sys.stderr.write(line.ljust(100))
    sys.stderr.flush()
    if final:
        sys.stderr.write("\n")
        sys.stderr.flush()
