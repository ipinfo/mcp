from ipinfo_mcp.pagination import paginate_ips


class TestPaginateIps:
    def test_single_page(self) -> None:
        ips = ["8.8.8.8", "1.1.1.1"]
        page_ips, meta = paginate_ips(ips, page=1, page_size=5)

        assert page_ips == ips
        assert meta == {
            "total_results": 2,
            "page": 1,
            "page_size": 5,
            "total_pages": 1,
            "has_next": False,
            "has_previous": False,
        }

    def test_second_page(self) -> None:
        ips = [f"1.0.0.{i}" for i in range(7)]
        page_ips, meta = paginate_ips(ips, page=2, page_size=5)

        assert meta["page"] == 2
        assert meta["total_pages"] == 2
        assert meta["has_next"] is False
        assert meta["has_previous"] is True
        assert len(page_ips) == 2

    def test_first_page_has_next(self) -> None:
        ips = [f"1.0.0.{i}" for i in range(7)]
        page_ips, meta = paginate_ips(ips, page=1, page_size=5)

        assert meta["has_next"] is True
        assert meta["has_previous"] is False
        assert len(page_ips) == 5

    def test_empty_results(self) -> None:
        page_ips, meta = paginate_ips([], page=1, page_size=5)

        assert meta["total_results"] == 0
        assert meta["total_pages"] == 0
        assert meta["has_next"] is False
        assert meta["has_previous"] is False
        assert page_ips == []

    def test_page_size_clamped_to_max(self) -> None:
        ips = [f"1.0.0.{i}" for i in range(30)]
        page_ips, meta = paginate_ips(ips, page=1, page_size=5000)

        assert meta["page_size"] == 1000
        assert len(page_ips) == 30

    def test_page_size_minimum_1(self) -> None:
        ips = ["8.8.8.8"]
        page_ips, meta = paginate_ips(ips, page=1, page_size=0)

        assert meta["page_size"] == 1
        assert len(page_ips) == 1

    def test_page_beyond_range_returns_empty(self) -> None:
        ips = ["8.8.8.8"]
        page_ips, meta = paginate_ips(ips, page=99, page_size=5)

        assert meta["page"] == 99
        assert page_ips == []

    def test_page_minimum_1(self) -> None:
        ips = ["8.8.8.8"]
        page_ips, meta = paginate_ips(ips, page=0, page_size=5)

        assert meta["page"] == 1
        assert len(page_ips) == 1

    def test_exact_page_boundary(self) -> None:
        ips = [f"1.0.0.{i}" for i in range(10)]
        page_ips, meta = paginate_ips(ips, page=2, page_size=5)

        assert meta["total_pages"] == 2
        assert meta["has_next"] is False
        assert len(page_ips) == 5
