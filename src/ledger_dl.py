"""
TLS 账本自动下载模块
从 Rapid7 Project Sonar 拉取最新的 TLS 扫描数据
"""

import asyncio
import logging
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("qian.ledger")

SONAR_BASE = "https://opendata.rapid7.com/sonar.ssl/"
DEFAULT_PORTS = [443, 8443, 2053, 2083, 2096, 2443]
MAX_CACHE_DAYS = 14


async def fetch_sonar_index() -> list[dict]:
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            url = f"{SONAR_BASE}index.json"
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(30),
                headers={"User-Agent": "IP-Reality/2.0"},
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
    except Exception as e:
        logger.warning(f"获取 Sonar 索引失败: {e}")
    return []


async def download_ledger(
    cache_dir: str = "./scans",
    ports: list[int] = None,
    force: bool = False,
) -> str | None:
    if ports is None:
        ports = DEFAULT_PORTS

    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    age_file = cache / ".last_update"
    if not force and age_file.exists():
        try:
            age = datetime.fromisoformat(age_file.read_text().strip())
            if datetime.now(timezone.utc).replace(tzinfo=None) - age < timedelta(days=MAX_CACHE_DAYS):
                existing = list(cache.glob("port-*.json.gz"))
                if existing:
                    logger.info(f"TLS 账本缓存有效 ({len(existing)} 文件, {age.date()})")
                    return cache_dir
        except Exception:
            pass

    logger.info("获取 Sonar SSL 索引 ...")
    index = await fetch_sonar_index()
    if not index:
        return None

    datasets = index if isinstance(index, list) else index.get("datasets", [])
    if not datasets:
        logger.warning("Sonar 索引为空")
        return None

    import aiohttp

    to_download = []
    port_pattern = re.compile(r"(?:port-|https_|[-_\.])(\d+)(?:[-_\.]|$)")

    for ds in datasets:
        files = ds.get("files", [])
        if isinstance(files, str):
            continue
        for f in files:
            fname = f.get("name", "") or f.get("key", "")
            if ".json.gz" not in fname:
                continue
            m = port_pattern.search(fname)
            if not m:
                continue
            file_port = int(m.group(1))
            if file_port not in ports:
                continue
            dl_url = f.get("download_url", "") or f.get("url", "")
            if not dl_url and "name" in f:
                dl_url = f"{SONAR_BASE}{f['name']}"
            if dl_url:
                to_download.append((file_port, dl_url, fname))

    if not to_download:
        logger.warning("未找到匹配端口的 TLS 账本文件")
        return None

    logger.info(f"下载 {len(to_download)} 个 TLS 账本文件 ...")

    async def download_one(port: int, url: str, fname: str):
        dst = cache / f"port-{port}-tls.json.gz"
        if dst.exists() and not force:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(600),
                    headers={"User-Agent": "IP-Reality/2.0"},
                ) as resp:
                    if resp.status == 200:
                        with open(dst, "wb") as fh:
                            async for chunk in resp.content.iter_chunked(1024 * 1024):
                                fh.write(chunk)
                        size_mb = dst.stat().st_size / (1024 * 1024)
                        logger.info(f"  ok port {port}: {size_mb:.0f} MB")
        except Exception as e:
            logger.warning(f"  fail port {port}: {e}")

    await asyncio.gather(*[download_one(p, u, n) for p, u, n in to_download], return_exceptions=True)

    age_file.write_text(datetime.now(timezone.utc).isoformat())

    remaining = list(cache.glob("port-*.json.gz"))
    logger.info(f"TLS 账本已就绪: {len(remaining)} 个文件")
    return cache_dir if remaining else None
