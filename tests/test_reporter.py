import json
import os

import pytest


class TestReporter:
    def test_start_finish_creates_file(self, tmp_path):
        from src.reporter import Reporter

        out = tmp_path / "test.json"
        r = Reporter(str(out))
        r.start()
        r.finish()
        assert out.exists()
        content = out.read_text()
        data = json.loads(content)
        assert isinstance(data, list)

    def test_on_result_writes_json(self, tmp_path):
        from src.reporter import Reporter

        out = tmp_path / "test.json"
        r = Reporter(str(out))
        r.start()
        r.on_result({
            "ip": "1.2.3.4",
            "port": 443,
            "target_sni": "apple.com",
            "common_name": "images.apple.com",
            "status": "AVAILABLE",
        })
        r.finish()

        data = json.loads(out.read_text())
        assert len(data) == 1
        assert data[0]["ip"] == "1.2.3.4"
        assert "timestamp" in data[0]
        assert "geo" in data[0]

    def test_lookup_geo_no_db(self):
        from src.reporter import _lookup_geo
        result = _lookup_geo("1.2.3.4")
        assert result == {}


class TestGeoIP:
    def test_reader_cache(self):
        from src.reporter import _geoip_cache
        assert isinstance(_geoip_cache, dict)
