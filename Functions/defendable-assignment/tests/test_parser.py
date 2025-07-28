# tests/test_parser.py
import pytest
from function_app import parse_cef  # adjust this path

def test_parse_cef_valid():
    cef = "CEF:0|Security|ThreatManager|1.0|100|Virus Detected|10|src=192.168.105.1 dst=10.133.130.157 spt=9730 dpt=46860 rt=1753693735"
    result = parse_cef(cef)
    assert result["cef_version"] == "0"
    assert result["device_product"] == "ThreatManager"
    assert result["device_vendor"] == "Security"
    assert result["device_version"] == "1.0"
    assert result["signature_id"] == "100"
    assert result["src"] == "192.168.105.1"
    assert result["dst"] == "10.133.130.157"
    assert result["spt"] == "9730"
    assert result["dpt"] == "46860"
    assert "rt" in result

def test_parse_cef_invalid():
    bad_cef = "Incomplete CEF line"
    result = parse_cef(bad_cef)
    assert "error" in result