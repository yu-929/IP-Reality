import asyncio

import pytest


class TestFetcher:
    def test_crtsh_query_format(self):
        from src.fetcher import _query_crtsh
        assert callable(_query_crtsh)

    def test_sniff_ports_empty(self):
        from src.fetcher import _sniff_ports
        result = asyncio.run(_sniff_ports([], [443, 8443], 1.0))
        assert result == set()

    def test_fetch_tls_ledger_no_files(self, tmp_path):
        from src.fetcher import fetch_tls_ledger
        result = asyncio.run(fetch_tls_ledger(str(tmp_path), "apple.com"))
        assert result == set()

    def test_resolve_domains_no_ipv6(self):
        from src.fetcher import _resolve_domains
        result = asyncio.run(_resolve_domains(["localhost"], no_ipv6=True))
        assert isinstance(result, set)


class TestVerifier:
    def test_is_redundancy_unreachable(self):
        from src.verifier import _is_redundancy
        result = asyncio.run(_is_redundancy("192.0.2.1", 443, 1.0))
        assert result is False

    def test_verify_single_unreachable(self):
        from src.verifier import verify_single
        result = asyncio.run(
            verify_single("192.0.2.1", 443, "apple.com", "cf.example.com", timeout=1.0)
        )
        assert result is None

    def test_verify_single_with_retries(self):
        from src.verifier import verify_single
        result = asyncio.run(
            verify_single("192.0.2.1", 443, "apple.com", "cf.example.com", timeout=0.5, retries=2)
        )
        assert result is None

    def test_verify_single_with_invalid_proxy(self):
        from src.verifier import verify_single
        result = asyncio.run(
            verify_single("192.0.2.1", 443, "apple.com", "cf.example.com",
                          timeout=0.5, proxy_url="socks5://127.0.0.1:9999")
        )
        assert result is None

    def test_verify_batch_empty(self):
        from src.verifier import verify_batch

        async def _run():
            results = []
            async for r in verify_batch([], ["apple.com"], "cf.example.com", progress=False):
                results.append(r)
            return results

        results = asyncio.run(_run())
        assert results == []


class TestExceptions:
    def test_exceptions_hierarchy(self):
        from src.exceptions import QianError, ConnectionError, TLSHandshakeError
        assert issubclass(ConnectionError, QianError)
        assert issubclass(TLSHandshakeError, QianError)
