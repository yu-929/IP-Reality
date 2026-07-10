"""
Phase 3: 数据富化 + 结构化输出模块
GeoIP, 终端实时打印, 流式 JSON 写入
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("xiao.reporter")

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C_GREEN = Fore.GREEN
    C_YELLOW = Fore.YELLOW
    C_CYAN = Fore.CYAN
    C_RESET = Style.RESET_ALL
except ImportError:
    C_GREEN = C_YELLOW = C_CYAN = C_RESET = ""


class Reporter:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.count = 0
        self._fp = None

    def start(self):
        self._fp = open(self.output_path, "w", encoding="utf-8")
        self._fp.write("[\n")

    def on_result(self, result: dict):
        result["geo"] = _lookup_geo(result["ip"])
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.count += 1

        geo = result["geo"]
        tag = f"{C_GREEN}[+]{C_RESET}"
        print(
            f"  {tag} {C_CYAN}{result['ip']}:{result['port']}{C_RESET}  "
            f"{C_YELLOW}{result['target_sni']}{C_RESET}  "
            f"[{geo.get('country', '??')}] {geo.get('asn', '')}"
        )

        if self.count > 1:
            self._fp.write(",\n")
        json.dump(result, self._fp, ensure_ascii=False, indent=2)

    def finish(self):
        self._fp.write("\n]\n")
        self._fp.close()
        logger.info(f"共发现 {self.count} 个配置特性节点 -> {self.output_path}")


_geoip_cache = {}


def _geoip_reader(path: str):
    if path not in _geoip_cache:
        import geoip2.database
        _geoip_cache[path] = geoip2.database.Reader(path)
    return _geoip_cache[path]


def _lookup_geo(ip: str) -> dict:
    db_path = os.environ.get("GEOIP_DB", "/usr/share/GeoIP/GeoLite2-City.mmdb")
    if not os.path.exists(db_path):
        return {}
    try:
        import geoip2.database
        reader = _geoip_reader(db_path)
        resp = reader.city(ip)
        return {
            "country": resp.country.iso_code or "??",
            "city": resp.city.name or "",
            "asn": "",
        }
    except ImportError:
        pass
    except Exception:
        pass
    return {}
