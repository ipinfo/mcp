from ipinfo_mcp.validation import validate_ips


class TestValidateIpsSoft:
    def test_all_valid(self) -> None:
        valid, errors = validate_ips(["8.8.8.8", "1.1.1.1"])
        assert valid == ["8.8.8.8", "1.1.1.1"]
        assert errors == {}

    def test_all_invalid(self) -> None:
        valid, errors = validate_ips(["not-an-ip", "also-bad"])
        assert valid == []
        assert len(errors) == 2
        assert "not-an-ip" in errors
        assert "also-bad" in errors

    def test_mixed_valid_and_invalid(self) -> None:
        valid, errors = validate_ips(["8.8.8.8", "not-valid", "1.1.1.1"])
        assert valid == ["8.8.8.8", "1.1.1.1"]
        assert len(errors) == 1
        assert "not-valid" in errors

    def test_private_ip_reported_as_error(self) -> None:
        valid, errors = validate_ips(["192.168.1.1"])
        assert valid == []
        assert "192.168.1.1" in errors

    def test_loopback_reported_as_error(self) -> None:
        valid, errors = validate_ips(["127.0.0.1"])
        assert valid == []
        assert "127.0.0.1" in errors

    def test_normalizes_ipv6(self) -> None:
        valid, errors = validate_ips(["2001:4860:4860::8888"])
        assert valid == ["2001:4860:4860::8888"]
        assert errors == {}

    def test_empty_list(self) -> None:
        valid, errors = validate_ips([])
        assert valid == []
        assert errors == {}

    def test_strips_whitespace(self) -> None:
        valid, errors = validate_ips(["  8.8.8.8  "])
        assert valid == ["8.8.8.8"]
        assert errors == {}
