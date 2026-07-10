#!/usr/bin/env python3
"""
qian — IP-Reality 节点发现工具
基于 CT 日志 + TLS 账本，双重握手验证，精准筛选可薅 CF 羊毛的 REALITY 节点。

用法:
  qian --sni images.apple.com --cf-domain my.cdn.domain
  qian --sni swdist.apple.com --cf-domain my.cdn.domain --ledger scans/
  qian --sni-list snis.txt --cf-domain my.cdn.domain
  qian   (菜单模式)
"""

import argparse
import asyncio
import logging
import os
import resource
import signal
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
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def setup_logging(verbose: bool, quiet: bool):
    """配置日志: INFO->stdout, DEBUG->file, WARNING/ERROR->stderr"""
    root = logging.getLogger("qian")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()

    if not quiet:
        h_stdout = logging.StreamHandler(sys.stdout)
        h_stdout.setLevel(logging.DEBUG if verbose else logging.INFO)
        h_stdout.addFilter(lambda r: r.levelno < logging.WARNING)
        h_stdout.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        root.addHandler(h_stdout)

    h_stderr = logging.StreamHandler(sys.stderr)
    h_stderr.setLevel(logging.WARNING)
    h_stderr.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root.addHandler(h_stderr)

    if verbose:
        fh = logging.FileHandler("qian-debug.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(message)s"))
        root.addHandler(fh)

    return logging.getLogger("qian")


def validate_args(args) -> list[str]:
    """启动配置验证，返回错误列表"""
    errors = []

    if args.ports:
        for p in args.ports.split(","):
            try:
                pn = int(p)
                if pn < 1 or pn > 65535:
                    errors.append(f"端口 {p} 超出范围 (1-65535)")
            except ValueError:
                errors.append(f"无效端口: {p}")

    if args.sni:
        for sni in [args.sni]:
            if not DOMAIN_RE.match(sni):
                errors.append(f"无效 SNI 格式: {sni}")

    if args.sni_list:
        p = Path(args.sni_list)
        if not p.exists():
            errors.append(f"SNI 列表文件不存在: {args.sni_list}")

    if args.cf_domain:
        if not DOMAIN_RE.match(args.cf_domain):
            errors.append(f"无效 CF 域名格式: {args.cf_domain}")

    if args.ledger:
        p = Path(args.ledger)
        if not p.exists():
            errors.append(f"TLS 账本目录不存在: {args.ledger}")

    if args.ledger_cache:
        try:
            Path(args.ledger_cache).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"无法创建缓存目录 {args.ledger_cache}: {e}")

    if args.concurrency < 1:
        errors.append(f"并发数必须 > 0: {args.concurrency}")
    if args.concurrency > 5000:
        errors.append(f"并发数过大 (最大 5000): {args.concurrency}")
    if args.timeout <= 0:
        errors.append(f"超时必须 > 0: {args.timeout}")

    return errors


async def menu_mode(args):
    """交互式菜单模式"""
    PRESETS = {
        "1": ("images.apple.com", "Apple CDN"),
        "2": ("swdist.apple.com", "Apple Software"),
        "3": ("download.microsoft.com", "Microsoft CDN"),
    }

    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        C = Fore.CYAN
        G = Fore.GREEN
        Y = Fore.YELLOW
        R = Style.RESET_ALL
    except ImportError:
        C = G = Y = R = ""

    logo = "QIAN  IP-Reality v2.0"
    print(f"\n{C}{'=' * 50}{R}")
    print(f"{C}  {logo}{R}")
    print(f"{C}{'=' * 50}{R}\n")

    # Step 1: SNI
    print(f"{Y}[?] 选择目标 SNI:{R}")
    for k, (sni, desc) in PRESETS.items():
        print(f"  {G}{k}{R}. {sni} ({desc})")
    print(f"  {G}c{R}. 自定义输入")
    choice = input(f"\n  选择 [1]: ").strip() or "1"

    snis = []
    if choice in PRESETS:
        snis.append(PRESETS[choice][0])
    else:
        custom = input("  输入 SNI: ").strip()
        if custom:
            snis.append(custom)
    if not snis:
        print(f"{Y}未输入 SNI，退出{R}")
        return

    # Step 2: CF domain
    cf_domain = args.cf_domain
    if not cf_domain:
        cf_domain = input(f"\n{Y}[?] 你的 Cloudflare 域名 (已开 CDN):{R} ").strip()
        if not cf_domain:
            print(f"{Y}CF 域名必填，退出{R}")
            return

    # Step 3: TLS ledger
    ledger = args.ledger
    if not ledger:
        use_ledger = input(f"\n{Y}[?] 使用 TLS 账本? (y/N):{R} ").strip().lower()
        if use_ledger == "y":
            ledger = input("  TLS 账本目录: ").strip()

    # Step 4: Concurrency
    concurrency = args.concurrency
    custom_cc = input(f"\n{Y}[?] 并发数 [{concurrency}]:{R} ").strip()
    if custom_cc:
        try:
            concurrency = int(custom_cc)
        except ValueError:
            pass

    # Step 5: Ports
    ports_str = args.ports
    custom_ports = input(f"{Y}[?] 端口 [{ports_str}]:{R} ").strip()
    if custom_ports:
        ports_str = custom_ports
    ports = [int(p) for p in ports_str.split(",")]

    print(f"\n{G}>> 开始抓取 ...{R}")
    print(f"  SNI: {G}{', '.join(snis)}{R}")
    print(f"  CF:  {G}{cf_domain}{R}")
    print(f"  并发: {concurrency}  端口: {ports_str}\n")

    await run_pipeline(
        snis, cf_domain, ports, ledger, concurrency,
        args.timeout, args.output, not args.no_redundancy,
        retries=1, proxy_url=None, progress=True, no_ipv6=False,
        shutdown_event=None,
    )


async def run_pipeline(
    snis: list[str],
    cf_domain: str,
    ports: list[int],
    ledger_dir: str | None,
    concurrency: int,
    timeout: float,
    output_path: str,
    redundancy_check: bool,
    retries: int = 1,
    proxy_url: str | None = None,
    progress: bool = True,
    no_ipv6: bool = False,
    shutdown_event: asyncio.Event | None = None,
):
    """执行 Phase 1-3 主流程"""
    logger = logging.getLogger("qian")
    all_targets: set[tuple[str, int]] = set()

    for sni in snis:
        logger.info(f"[Phase 1A] CT 日志: {sni}")
        targets = await fetch_ct_logs(sni, ports, timeout, no_ipv6=no_ipv6)
        all_targets.update(targets)
        logger.info(f"  -> {len(targets)} 候选")

    if ledger_dir:
        for sni in snis:
            logger.info(f"[Phase 1B] TLS 账本: {sni}")
            targets = await fetch_tls_ledger(ledger_dir, sni)
            all_targets.update(targets)
            logger.info(f"  -> {len(targets)} 候选")

    if shutdown_event and shutdown_event.is_set():
        return

    if not all_targets:
        logger.error("未获取到任何候选节点，请检查 SNI 或网络")
        sys.exit(1)

    target_list = list(all_targets)
    logger.info(f"总计 {len(target_list)} 个待验证 IP:PORT")

    reporter = Reporter(output_path)
    reporter.start()

    logger.info(f"[Phase 2] 双重 TLS 交叉验证 (并发 {concurrency})")
    async for result in verify_batch(
        target_list, snis, cf_domain,
        concurrency=concurrency,
        timeout=timeout,
        redundancy_check=redundancy_check,
        retries=retries,
        proxy_url=proxy_url,
        shutdown_event=shutdown_event,
        progress=progress,
    ):
        reporter.on_result(result)

    reporter.finish()
    logger.info(f"完成 -> {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="qian",
        description="IP-Reality 节点发现 — 基于 CT 日志 + TLS 账本的 REALITY 配置特性检测",
    )
    parser.add_argument("--sni", help="目标大厂 SNI (如 images.apple.com)")
    parser.add_argument("--sni-list", help="SNI 列表文件，一行一个")
    parser.add_argument("--cf-domain", help="你的 Cloudflare 域名 (必须开启 CDN 小黄云)")
    parser.add_argument("--ledger", help="TLS 账本目录 (含 port-*-tls.json.gz)")
    parser.add_argument("--auto-ledger", action="store_true", default=True,
                        help="自动下载最新 TLS 账本 (默认开启)")
    parser.add_argument("--no-ledger", action="store_true",
                        help="跳过 TLS 账本，仅用 CT 日志")
    parser.add_argument("--ledger-cache", default="./scans",
                        help="TLS 账本缓存目录 (默认 ./scans)")
    parser.add_argument("--ports", default="443,8443,2053,2083,2096,2443",
                        help="伴随嗅探端口 (默认 443,8443,2053,2083,2096,2443)")
    parser.add_argument("--concurrency", type=int, default=500,
                        help="验证并发数 (默认 500)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="单次握手超时秒数 (默认 3.0)")
    parser.add_argument("--output", default="qian_result.json",
                        help="输出文件路径 (默认 qian_result.json)")
    parser.add_argument("--no-redundancy", action="store_true",
                        help="关闭冗余检测")
    parser.add_argument("--retry", type=int, default=1,
                        help="TLS 握手重试次数 (默认 1，即不重试)")
    parser.add_argument("--proxy", default=None,
                        help="SOCKS5/HTTP 代理 (如 socks5://127.0.0.1:1080)")
    parser.add_argument("--no-progress", action="store_true",
                        help="关闭进度条显示")
    parser.add_argument("--no-ipv6", action="store_true",
                        help="跳过 IPv6 地址解析")
    parser.add_argument("--verbose", action="store_true",
                        help="详细日志 (DEBUG 级别，写入 qian-debug.log)")
    parser.add_argument("--quiet", action="store_true",
                        help="安静模式 (仅错误输出)")
    args = parser.parse_args()

    logger = setup_logging(args.verbose, args.quiet)

    # ── 配置验证 ──
    errors = validate_args(args)
    if errors:
        for e in errors:
            logger.error(f"配置错误: {e}")
        sys.exit(1)

    # ── SNI 列表 ──
    snis = []
    if args.sni:
        snis.append(args.sni.strip())
    if args.sni_list:
        with open(args.sni_list, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    snis.append(line)
    if not snis:
        asyncio.run(menu_mode(args))
        return

    # ── CF 域名检查 ──
    cf_domain = args.cf_domain
    if not cf_domain:
        logger.error("必须提供 --cf-domain (你的 Cloudflare 域名，已开启 CDN)")
        logger.info("用法: qian --sni images.apple.com --cf-domain my.cdn.domain")
        sys.exit(1)

    ports = [int(p) for p in args.ports.split(",")]

    async def _run():
        shutdown_event = asyncio.Event()

        # ── Graceful Shutdown ──
        loop_ref = asyncio.get_running_loop()

        def _sig_handler():
            logger.warning("收到中断信号，正在优雅退出 ...")
            shutdown_event.set()
            for task in asyncio.all_tasks(loop_ref):
                task.cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop_ref.add_signal_handler(sig, _sig_handler)
            except NotImplementedError:
                signal.signal(sig, lambda s, f: _sig_handler())

        # ── Phase 1A: CT 日志 ──
        all_targets: set[tuple[str, int]] = set()

        for sni in snis:
            if shutdown_event.is_set():
                return
            logger.info(f"[Phase 1A] CT 日志: {sni}")
            targets = await fetch_ct_logs(sni, ports, args.timeout, no_ipv6=args.no_ipv6)
            all_targets.update(targets)
            logger.info(f"  -> {len(targets)} 候选")

        # ── Phase 1B: TLS 账本 ──
        ledger_dir = args.ledger
        if args.auto_ledger and not args.no_ledger:
            from .ledger_dl import download_ledger
            ledger_dir = await download_ledger(args.ledger_cache, ports)

        if ledger_dir and not args.no_ledger:
            for sni in snis:
                if shutdown_event.is_set():
                    return
                logger.info(f"[Phase 1B] TLS 账本: {sni}")
                targets = await fetch_tls_ledger(ledger_dir, sni)
                all_targets.update(targets)
                logger.info(f"  -> {len(targets)} 候选")

        if shutdown_event.is_set():
            return

        if not all_targets:
            logger.error("未获取到任何候选节点，请检查 SNI 或网络")
            sys.exit(1)

        target_list = list(all_targets)
        logger.info(f"总计 {len(target_list)} 个待验证 IP:PORT")

        reporter = Reporter(args.output)
        reporter.start()

        logger.info(f"[Phase 2] 双重 TLS 交叉验证 (并发 {args.concurrency})")
        async for result in verify_batch(
            target_list, snis, cf_domain,
            concurrency=args.concurrency,
            timeout=args.timeout,
            redundancy_check=not args.no_redundancy,
            retries=args.retry,
            proxy_url=args.proxy,
            shutdown_event=shutdown_event,
            progress=not args.no_progress,
        ):
            reporter.on_result(result)

        reporter.finish()
        logger.info(f"完成 -> {args.output}")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print()
        logger.info("用户中断")


if __name__ == "__main__":
    main()
