import pytest
from app.core.pcap_parser import parse_pcap, parse_pcap_safe


def test_parse_returns_packets():
    packets = parse_pcap("sample_data/test.pcap")
    assert len(packets) > 0                    # что-то разобралось
    first = packets[0]
    assert "src_ip" in first                   # есть нужные поля
    assert "dst_ip" in first
    assert first["protocol"] in ("TCP", "UDP", "ICMP", "OTHER")

# проверяет защиту по расширению
def test_safe_rejects_wrong_extension():
    with pytest.raises(ValueError):
        parse_pcap_safe("sample_data/test.txt")

# проверяет защиту от несуществующего файла
def test_safe_rejects_missing_file():
    with pytest.raises(ValueError):
        parse_pcap_safe("sample_data/no_such_file.pcap")
