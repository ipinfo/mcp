from ipinfo_mcp.cache import IPCache

TOKEN = "token_a"
OTHER_TOKEN = "token_b"


class TestIPCachePutGet:
    def test_get_returns_none_for_missing_key(self) -> None:
        cache = IPCache()
        assert cache.get(TOKEN, "lite", "8.8.8.8") is None

    def test_put_and_get_single_entry(self) -> None:
        cache = IPCache()
        data = {"ip": "8.8.8.8", "country": "US"}
        cache.put(TOKEN, "lite", "8.8.8.8", data)
        assert cache.get(TOKEN, "lite", "8.8.8.8") == data

    def test_namespaces_are_isolated(self) -> None:
        cache = IPCache()
        lite_data = {"ip": "8.8.8.8", "country": "US"}
        lookup_data = {"ip": "8.8.8.8", "city": "Mountain View"}
        cache.put(TOKEN, "lite", "8.8.8.8", lite_data)
        cache.put(TOKEN, "lookup", "8.8.8.8", lookup_data)

        assert cache.get(TOKEN, "lite", "8.8.8.8") == lite_data
        assert cache.get(TOKEN, "lookup", "8.8.8.8") == lookup_data

    def test_put_overwrites_existing(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"old": True})
        cache.put(TOKEN, "lite", "8.8.8.8", {"new": True})
        assert cache.get(TOKEN, "lite", "8.8.8.8") == {"new": True}


class TestIPCacheTokenIsolation:
    def test_other_token_does_not_see_entry(self) -> None:
        """One token's results must never be served to another token."""
        cache = IPCache()
        cache.put(TOKEN, "resproxy", "8.8.8.8", {"service": "NordVPN"})

        assert cache.get(OTHER_TOKEN, "resproxy", "8.8.8.8") is None

    def test_other_token_reports_a_miss(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"ip": "8.8.8.8"})

        cached, misses = cache.get_many(OTHER_TOKEN, "lite", ["8.8.8.8"])
        assert cached == {}
        assert misses == ["8.8.8.8"]

    def test_tokens_hold_independent_entries_for_same_ip(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "resproxy", "8.8.8.8", {})
        cache.put(OTHER_TOKEN, "resproxy", "8.8.8.8", {"service": "NordVPN"})

        assert cache.get(TOKEN, "resproxy", "8.8.8.8") == {}
        assert cache.get(OTHER_TOKEN, "resproxy", "8.8.8.8") == {"service": "NordVPN"}

    def test_store_does_not_hold_plaintext_tokens(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"ip": "8.8.8.8"})

        assert all(TOKEN not in key for key in cache._store)


class TestIPCacheGetMany:
    def test_all_cached(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"ip": "8.8.8.8"})
        cache.put(TOKEN, "lite", "1.1.1.1", {"ip": "1.1.1.1"})

        cached, misses = cache.get_many(TOKEN, "lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {"8.8.8.8": {"ip": "8.8.8.8"}, "1.1.1.1": {"ip": "1.1.1.1"}}
        assert misses == []

    def test_all_missing(self) -> None:
        cache = IPCache()
        cached, misses = cache.get_many(TOKEN, "lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {}
        assert misses == ["8.8.8.8", "1.1.1.1"]

    def test_partial_cache(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"ip": "8.8.8.8"})

        cached, misses = cache.get_many(TOKEN, "lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {"8.8.8.8": {"ip": "8.8.8.8"}}
        assert misses == ["1.1.1.1"]

    def test_empty_list(self) -> None:
        cache = IPCache()
        cached, misses = cache.get_many(TOKEN, "lite", [])
        assert cached == {}
        assert misses == []

    def test_uses_correct_namespace(self) -> None:
        cache = IPCache()
        cache.put(TOKEN, "lite", "8.8.8.8", {"ip": "8.8.8.8"})

        cached, misses = cache.get_many(TOKEN, "lookup", ["8.8.8.8"])
        assert cached == {}
        assert misses == ["8.8.8.8"]


class TestIPCachePutMany:
    def test_put_many_stores_all(self) -> None:
        cache = IPCache()
        items = {
            "8.8.8.8": {"ip": "8.8.8.8"},
            "1.1.1.1": {"ip": "1.1.1.1"},
        }
        cache.put_many(TOKEN, "lite", items)

        assert cache.get(TOKEN, "lite", "8.8.8.8") == {"ip": "8.8.8.8"}
        assert cache.get(TOKEN, "lite", "1.1.1.1") == {"ip": "1.1.1.1"}

    def test_put_many_empty_dict(self) -> None:
        cache = IPCache()
        cache.put_many(TOKEN, "lite", {})
        assert cache.get(TOKEN, "lite", "8.8.8.8") is None

    def test_put_many_is_scoped_to_token(self) -> None:
        cache = IPCache()
        cache.put_many(TOKEN, "lite", {"8.8.8.8": {"ip": "8.8.8.8"}})

        assert cache.get(OTHER_TOKEN, "lite", "8.8.8.8") is None
