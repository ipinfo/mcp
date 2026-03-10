from ipinfo_mcp.cache import IPCache


class TestIPCachePutGet:
    def test_get_returns_none_for_missing_key(self) -> None:
        cache = IPCache()
        assert cache.get("lite", "8.8.8.8") is None

    def test_put_and_get_single_entry(self) -> None:
        cache = IPCache()
        data = {"ip": "8.8.8.8", "country": "US"}
        cache.put("lite", "8.8.8.8", data)
        assert cache.get("lite", "8.8.8.8") == data

    def test_namespaces_are_isolated(self) -> None:
        cache = IPCache()
        lite_data = {"ip": "8.8.8.8", "country": "US"}
        lookup_data = {"ip": "8.8.8.8", "city": "Mountain View"}
        cache.put("lite", "8.8.8.8", lite_data)
        cache.put("lookup", "8.8.8.8", lookup_data)

        assert cache.get("lite", "8.8.8.8") == lite_data
        assert cache.get("lookup", "8.8.8.8") == lookup_data

    def test_put_overwrites_existing(self) -> None:
        cache = IPCache()
        cache.put("lite", "8.8.8.8", {"old": True})
        cache.put("lite", "8.8.8.8", {"new": True})
        assert cache.get("lite", "8.8.8.8") == {"new": True}


class TestIPCacheGetMany:
    def test_all_cached(self) -> None:
        cache = IPCache()
        cache.put("lite", "8.8.8.8", {"ip": "8.8.8.8"})
        cache.put("lite", "1.1.1.1", {"ip": "1.1.1.1"})

        cached, misses = cache.get_many("lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {"8.8.8.8": {"ip": "8.8.8.8"}, "1.1.1.1": {"ip": "1.1.1.1"}}
        assert misses == []

    def test_all_missing(self) -> None:
        cache = IPCache()
        cached, misses = cache.get_many("lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {}
        assert misses == ["8.8.8.8", "1.1.1.1"]

    def test_partial_cache(self) -> None:
        cache = IPCache()
        cache.put("lite", "8.8.8.8", {"ip": "8.8.8.8"})

        cached, misses = cache.get_many("lite", ["8.8.8.8", "1.1.1.1"])
        assert cached == {"8.8.8.8": {"ip": "8.8.8.8"}}
        assert misses == ["1.1.1.1"]

    def test_empty_list(self) -> None:
        cache = IPCache()
        cached, misses = cache.get_many("lite", [])
        assert cached == {}
        assert misses == []

    def test_uses_correct_namespace(self) -> None:
        cache = IPCache()
        cache.put("lite", "8.8.8.8", {"ip": "8.8.8.8"})

        cached, misses = cache.get_many("lookup", ["8.8.8.8"])
        assert cached == {}
        assert misses == ["8.8.8.8"]


class TestIPCachePutMany:
    def test_put_many_stores_all(self) -> None:
        cache = IPCache()
        items = {
            "8.8.8.8": {"ip": "8.8.8.8"},
            "1.1.1.1": {"ip": "1.1.1.1"},
        }
        cache.put_many("lite", items)

        assert cache.get("lite", "8.8.8.8") == {"ip": "8.8.8.8"}
        assert cache.get("lite", "1.1.1.1") == {"ip": "1.1.1.1"}

    def test_put_many_empty_dict(self) -> None:
        cache = IPCache()
        cache.put_many("lite", {})
        assert cache.get("lite", "8.8.8.8") is None
