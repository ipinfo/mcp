from ipinfo_mcp.pagination import paginate


class TestPaginate:
    def test_single_page(self) -> None:
        results = [
            {"ip": "8.8.8.8", "country": "US"},
            {"ip": "1.1.1.1", "country": "AU"},
        ]
        output = paginate(results, page=1, page_size=5)

        assert output["_pagination"] == {
            "total_results": 2,
            "page": 1,
            "page_size": 5,
            "total_pages": 1,
            "has_next": False,
            "has_previous": False,
        }
        assert output["results"] == results

    def test_second_page(self) -> None:
        results = [{"ip": f"1.0.0.{i}"} for i in range(7)]
        output = paginate(results, page=2, page_size=5)

        assert output["_pagination"]["page"] == 2
        assert output["_pagination"]["total_pages"] == 2
        assert output["_pagination"]["has_next"] is False
        assert output["_pagination"]["has_previous"] is True
        assert len(output["results"]) == 2

    def test_first_page_has_next(self) -> None:
        results = [{"ip": f"1.0.0.{i}"} for i in range(7)]
        output = paginate(results, page=1, page_size=5)

        assert output["_pagination"]["has_next"] is True
        assert output["_pagination"]["has_previous"] is False
        assert len(output["results"]) == 5

    def test_empty_results(self) -> None:
        output = paginate([], page=1, page_size=5)

        assert output["_pagination"]["total_results"] == 0
        assert output["_pagination"]["total_pages"] == 0
        assert output["_pagination"]["has_next"] is False
        assert output["_pagination"]["has_previous"] is False
        assert output["results"] == []

    def test_page_size_clamped_to_max_25(self) -> None:
        results = [{"ip": f"1.0.0.{i}"} for i in range(30)]
        output = paginate(results, page=1, page_size=50)

        assert output["_pagination"]["page_size"] == 25
        assert len(output["results"]) == 25

    def test_page_size_minimum_1(self) -> None:
        results = [{"ip": "8.8.8.8"}]
        output = paginate(results, page=1, page_size=0)

        assert output["_pagination"]["page_size"] == 1
        assert len(output["results"]) == 1

    def test_page_beyond_range_returns_empty(self) -> None:
        results = [{"ip": "8.8.8.8"}]
        output = paginate(results, page=99, page_size=5)

        assert output["_pagination"]["page"] == 99
        assert output["results"] == []

    def test_page_minimum_1(self) -> None:
        results = [{"ip": "8.8.8.8"}]
        output = paginate(results, page=0, page_size=5)

        assert output["_pagination"]["page"] == 1
        assert len(output["results"]) == 1

    def test_exact_page_boundary(self) -> None:
        results = [{"ip": f"1.0.0.{i}"} for i in range(10)]
        output = paginate(results, page=2, page_size=5)

        assert output["_pagination"]["total_pages"] == 2
        assert output["_pagination"]["has_next"] is False
        assert len(output["results"]) == 5
