#!/usr/bin/env python3
"""
xiao — IP-Reality 节点发现工具

用法:
  xiao images.apple.com my.cf.domain          # 位置参数
  xiao                                       # 菜单模式
  xiao -l snis.txt my.cf.domain              # 批量 SNI
  xiao -p 2 my.cf.domain                     # 预设 SNI: 2=swdist.apple.com
"""

import argparse
import asyncio
import logging
import os
import resource
import signal
import subprocess
import sys
import re
from pathlib import Path

try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
except Exception:
    pass

from .fetcher import fetch_ct_logs, fetch_tls_ledger
from .verifier import verify_batch
from .reporter import Reporter

DEFAULT_PORTS = [443, 8443, 2053, 2083, 2096, 2443]
PRESET_SNI = {
    "1": "images.apple.com",
    "2": "swdist.apple.com",
    "3": "swcdn.apple.com",
    "4": "updates.cdn-apple.com",
    "5": "download.microsoft.com",
}
CF_CONFIG = Path.home() / ".xiao-cf"
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _smart_concurrency():
    """根据系统 ulimit 自动计算最优并发数"""
    try:
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        return max(200, min(limit // 2, 2000))
    except Exception:
        return 500


def _last_cf_domain() -> str | None:
    """读取上次使用的 CF 域名"""
    try:
        if CF_CONFIG.exists():
            return CF_CONFIG.read_text().strip()
    except Exception:
        pass
    return None


def _save_cf_domain(domain: str):
    """记忆 CF 域名"""
    try:
        CF_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CF_CONFIG.write_text(domain)
    except Exception:
        pass


def _do_uninstall():
    """卸载 xiao — 移除包、命令和配置"""
    repo = Path(__file__).resolve().parent.parent
    cf = CF_CONFIG
    bins = [
        Path("/usr/local/bin/xiao"),
        Path("/usr/bin/xiao"),
    ]

    print("xiao uninstall ...")

    # 卸载 pip 包
    r = subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "-y", "ip-reality"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        print("  pip: 已移除 ip-reality 包")

    # 删除全局命令
    for b in bins:
        if b.exists():
            b.unlink()
            print(f"  bin: 已删除 {b}")

    # 删除 CF 域名记忆
    if cf.exists():
        cf.unlink()
        print(f"  cfg: 已删除 {cf}")

    # 删除项目目录（如果是 pip install -e 方式）
    if repo.exists() and repo.name == "IP-Reality":
        import shutil
        shutil.rmtree(repo, ignore_errors=True)
        print(f"  dir: 已删除 {repo}")

    print("卸载完成")


def setup_logging(verbose: bool, quiet: bool):
    root = logging.getLogger("xiao")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()

    if quiet:
        return logging.getLogger("xiao")

    fmt = logging.Formatter("[%(name)s] %(message)s")

    h_stderr = logging.StreamHandler(sys.stderr)
    h_stderr.setLevel(logging.WARNING)
    h_stderr.setFormatter(fmt)
    root.addHandler(h_stderr)

    h_stdout = logging.StreamHandler(sys.stdout)
    h_stdout.setLevel(logging.INFO)
    h_stdout.addFilter(lambda r: r.levelno < logging.WARNING)
    h_stdout.setFormatter(fmt)
    root.addHandler(h_stdout)

    if verbose:
        fh = logging.FileHandler("xiao-debug.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(message)s"))
        root.addHandler(fh)

    return logging.getLogger("xiao")


async def menu_mode(args):
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        C = Fore.CYAN; G = Fore.GREEN; Y = Fore.YELLOW; R = Style.RESET_ALL
    except ImportError:
        C = G = Y = R = ""

    print(f"\n{G}xiao  IP-Reality{R}")
    print(f"{C}{'─' * 36}{R}")

    # Step 1: SNI — 一行搞定
    print(f"\n  {Y}预设 SNI:{R}")
    for k, sni in PRESET_SNI.items():
        print(f"    {G}{k}{R}. {sni}")
    print(f"    {G}c{R}. 自定义")

    saved = _last_cf_domain()
    choice = input(f"\n  SNI [1]: ").strip() or "1"
    if choice == "c":
        snis = [input("  输入 SNI: ").strip()] or None
    elif choice in PRESET_SNI:
        snis = [PRESET_SNI[choice]]
    else:
        snis = [PRESET_SNI["1"]]

    if not snis or not snis[0]:
        print(f"{Y}未输入 SNI，退出{R}")
        return

    # Step 2: CF 域名 — 记忆上次
    cf_domain = args.cf_domain
    if not cf_domain:
        hint = f" [{saved}]" if saved else ""
        cf_domain = input(f"  CF 域名{hint}: ").strip()
        if not cf_domain:
            cf_domain = saved
    if not cf_domain:
        print(f"{Y}CF 域名必填，退出{R}")
        return
    _save_cf_domain(cf_domain)

    print(f"\n  {G}>> {snis[0]}  @  {cf_domain}{R}\n")

    await run_pipeline(snis, cf_domain, DEFAULT_PORTS, args.ledger,
                       args.concurrency, args.timeout, args.output,
                       not args.no_redundancy,
                       proxy_url=args.proxy)


async def run_pipeline(
    snis, cf_domain, ports, ledger_dir,
    concurrency, timeout, output_path, redundancy_check,
    retries=1, proxy_url=None, progress=True, no_ipv6=False,
    shutdown_event=None,
):
    logger = logging.getLogger("xiao")
    all_targets: set[tuple[str, int]] = set()

    for sni in snis:
        if shutdown_event and shutdown_event.is_set():
            return
        targets = await fetch_ct_logs(sni, ports, timeout, no_ipv6=no_ipv6, proxy_url=proxy_url)
        all_targets.update(targets)

    if ledger_dir:
        for sni in snis:
            if shutdown_event and shutdown_event.is_set():
                return
            targets = await fetch_tls_ledger(ledger_dir, sni)
            all_targets.update(targets)

    if shutdown_event and shutdown_event.is_set():
        return

    if not all_targets:
        logger.error("未获取到候选节点")
        sys.exit(1)

    target_list = list(all_targets)

    reporter = Reporter(output_path)
    reporter.start()

    logger.info(f"候选 {len(target_list)} | 并发 {concurrency} | 超时 {timeout}s")
    async for result in verify_batch(
        target_list, snis, cf_domain,
        concurrency=concurrency, timeout=timeout,
        redundancy_check=redundancy_check,
        retries=retries, proxy_url=proxy_url,
        shutdown_event=shutdown_event, progress=progress,
    ):
        reporter.on_result(result)

    reporter.finish()
    logger.info(f">> {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="xiao",
        description="IP-Reality 节点发现",
        usage="xiao [SNI] [CF_DOMAIN] [选项]",
    )
    parser.add_argument("sni_pos", nargs="?", default=None, help="目标 SNI (位置参数)")
    parser.add_argument("cf_pos", nargs="?", default=None, help="CF 域名 (位置参数)")
    parser.add_argument("--sni", "-s", default=None, help="目标 SNI")
    parser.add_argument("--sni-list", "-l", default=None, help="SNI 列表文件")
    parser.add_argument("--cf-domain", "-c", default=None, help="CF 域名")
    parser.add_argument("--preset", "-p", choices=list(PRESET_SNI.keys()),
                        help="预设 SNI (1-5)")
    parser.add_argument("--ledger", help="TLS 账本目录")
    parser.add_argument("--no-ledger", action="store_true", help="跳过 TLS 账本")
    parser.add_argument("--ports", default="443,8443,2053,2083,2096,2443")
    parser.add_argument("--concurrency", type=int, default=_smart_concurrency(),
                        help=f"并发数 (默认: {_smart_concurrency()})")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--output", default="xiao_result.json")
    parser.add_argument("--no-redundancy", action="store_true")
    parser.add_argument("--retry", type=int, default=1)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--no-progress", action="store_true")
    parser.add_argument("--no-ipv6", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--update", "-u", action="store_true",
                        help="更新到最新版本")
    parser.add_argument("--uninstall", action="store_true",
                        help="卸载 xiao")
    args = parser.parse_args()

    logger = setup_logging(args.verbose, args.quiet)

    if args.uninstall:
        _do_uninstall()
        return

    if args.update:
        _do_update()
        return

    # ── SNI 解析 ──
    snis = []

    if args.preset:
        snis.append(PRESET_SNI[args.preset])

    if args.sni:
        snis.append(args.sni.strip())
    if args.sni_pos:
        if not snis:
            snis.append(args.sni_pos.strip())

    if args.sni_list:
        with open(args.sni_list, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    snis.append(line)

    # ── CF 域名解析 ──
    cf_domain = args.cf_domain or args.cf_pos
    if not cf_domain:
        cf_domain = _last_cf_domain()

    if not snis:
        asyncio.run(menu_mode(args))
        return

    if not cf_domain:
        logger.error("缺少 CF 域名。用法: xiao images.apple.com my.cf.domain")
        sys.exit(1)

    _save_cf_domain(cf_domain)
    ports = [int(p) for p in args.ports.split(",")]

    # ── 运行 ──
    async def _run():
        shutdown_event = asyncio.Event()
        loop_ref = asyncio.get_running_loop()

        def _sig_handler():
            shutdown_event.set()
            for task in asyncio.all_tasks(loop_ref):
                task.cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop_ref.add_signal_handler(sig, _sig_handler)
            except NotImplementedError:
                signal.signal(sig, lambda s, f: _sig_handler())

        all_targets: set[tuple[str, int]] = set()

        for sni in snis:
            if shutdown_event.is_set():
                return
            targets = await fetch_ct_logs(sni, ports, args.timeout, no_ipv6=args.no_ipv6, proxy_url=args.proxy)
            all_targets.update(targets)

        ledger_dir = args.ledger
        if not args.no_ledger and not ledger_dir:
            from .ledger_dl import download_ledger
            try:
                ledger_dir = await download_ledger("./scans", ports, proxy_url=args.proxy)
            except Exception:
                pass

        if ledger_dir and not args.no_ledger:
            for sni in snis:
                if shutdown_event.is_set():
                    return
                targets = await fetch_tls_ledger(ledger_dir, sni)
                all_targets.update(targets)

        if shutdown_event.is_set():
            return

        if not all_targets:
            logger.error("未获取到候选节点")
            sys.exit(1)

        target_list = list(all_targets)

        reporter = Reporter(args.output)
        reporter.start()

        logger.info(f"候选 {len(target_list)} | 并发 {args.concurrency} | 超时 {args.timeout}s")
        async for result in verify_batch(
            target_list, snis, cf_domain,
            concurrency=args.concurrency, timeout=args.timeout,
            redundancy_check=not args.no_redundancy,
            retries=args.retry, proxy_url=args.proxy,
            shutdown_event=shutdown_event,
            progress=not args.no_progress,
        ):
            reporter.on_result(result)

        reporter.finish()
        logger.info(f">> {args.output}")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print()
        logger.info("中断")


if __name__ == "__main__":
    main()
