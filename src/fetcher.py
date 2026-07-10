"""
Phase 1: 资产收集模块
  A: CT 日志 + DNS + 伴随端口嗅探
  B: TLS 历史账本流式过滤
"""

import asyncio
import gzip
import json
import logging
import re
from pathlib import Path

logger = logging.getLogger("qian.fetcher")

CRTSH_MIN_INTERVAL = 1.2  # crt.sh 请求最小间隔 (秒)


# ── Phase 1A: CT 日志 ──

async def fetch_ct_logs(sni: str, ports: list[int], timeout: float, no_ipv6: bool = False) -> set[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()

    subdomains = await _query_crtsh(sni, timeout)
    if not subdomains:
        logger.warning(f"  crt.sh 无结果: {sni}")
        return targets

    subdomains = list(set(subdomains))
    logger.info(f"  crt.sh -> {len(subdomains)} 个子域")

    ips = await _resolve_domains(subdomains, no_ipv6=no_ipv6)
    logger.info(f"  DNS -> {len(ips)} 个唯一 IP")

    targets = await _sniff_ports(list(ips), ports, timeout)
    logger.info(f"  端口嗅探 -> {len(targets)} 个开放")

    return targets


async def _query_crtsh(sni: str, timeout: float) -> list[str]:
    import aiohttp

    url = f"https://crt.sh/?q=%25.{sni}&output=json"
    retries = 3

    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout + 10),
                    headers={"User-Agent": "IP-Reality/2.0"},
                ) as resp:
                    if resp.status == 429:
                        wait = 30 * (attempt + 1)
                        logger.debug(f"  crt.sh 429, 等待 {wait}s")
                        await asyncio.sleep(wait)
                        continue
                    if resp.status != 200:
                        logger.debug(f"  crt.sh HTTP {resp.status}")
                        return []
                    data = await resp.json()
                    break
        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
            else:
                logger.debug(f"  crt.sh 请求失败: {e}")
                return []

    if data is None:
        return []

    domains = set()
    for entry in data:
        for key in ("name_value", "common_name"):
            val = entry.get(key, "")
            if val:
                for name in val.split("\n"):
                    name = name.strip().lower()
                    if not name or name.startswith("*"):
                        continue
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                        continue
                    if sni.lower() in name:
                        domains.add(name)

    await asyncio.sleep(CRTSH_MIN_INTERVAL)
    return list(domains)


async def _resolve_domains(domains: list[str], no_ipv6: bool = False) -> set[str]:
    ips: set[str] = set()

    try:
        import aiodns

        resolver = aiodns.DNSResolver()
        sem = asyncio.Semaphore(200)

        async def resolve(domain: str):
            async with sem:
                try:
                    result = await resolver.query_dns(domain, "A")
                    for r in result:
                        ips.add(r.host)
                except Exception:
                    pass
                if not no_ipv6:
                    try:
                        result = await resolver.query_dns(domain, "AAAA")
                        for r in result:
                            ips.add(r.host)
                    except Exception:
                        pass

        await asyncio.gather(*[resolve(d) for d in domains], return_exceptions=True)
    except ImportError:
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(200)

        async def resolve(domain: str):
            async with sem:
                try:
                    for fam in (0,):  # AF_INET only for fallback
                        result = await loop.getaddrinfo(domain, None, family=fam)
                        for r in result:
                            ips.add(r[4][0])
                except Exception:
                    pass

        await asyncio.gather(*[resolve(d) for d in domains], return_exceptions=True)

    return ips


async def _sniff_ports(ips: list[str], ports: list[int], timeout: float) -> set[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()
    sem = asyncio.Semaphore(300)

    async def probe(ip: str, port: int):
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=min(timeout, 2.0)
                )
                writer.close()
                await writer.wait_closed()
                targets.add((ip, port))
            except Exception:
                pass

    tasks = [probe(ip, port) for ip in ips for port in ports]
    await asyncio.gather(*tasks, return_exceptions=True)
    return targets


# ── Phase 1B: TLS 历史账本 ──

async def fetch_tls_ledger(ledger_dir: str, sni: str) -> set[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()
    path = Path(ledger_dir)
    sni_lower = sni.lower()
    ipv4_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
    ipv6_pattern = re.compile(r"^[0-9a-fA-F:]+$")

    sem = asyncio.Semaphore(4)

    async def process_file(filepath: Path, port: int):
        async with sem:
            try:
                with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if sni_lower not in line.lower():
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        server_name = str(record.get("server_name", "") or record.get("name", "")).lower()
                        if sni_lower not in server_name:
                            continue
                        ip = str(record.get("ip", ""))
                        if ipv4_pattern.match(ip) or ipv6_pattern.match(ip):
                            targets.add((ip.strip(), port))
            except Exception as e:
                logger.debug(f"  读取 {filepath.name} 失败: {e}")

    ledger_path = Path(ledger_dir)
    tasks = []
    port_pattern = re.compile(r"(?:port-|https_|[-_\.])(\d+)(?:[-_\.]|$)")
    for f in ledger_path.glob("*.json.gz"):
        m = port_pattern.search(f.name)
        if m:
            port = int(m.group(1))
            tasks.append(process_file(f, port))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    else:
        logger.warning(f"  未找到 .json.gz 账本文件于 {ledger_dir}")

    return targets
