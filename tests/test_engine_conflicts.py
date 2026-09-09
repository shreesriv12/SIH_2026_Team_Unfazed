from core.analyzer import engine_conflicts


def test_equivalent_tshark_and_zeek_values_are_not_conflicts():
    assert engine_conflicts("TLS 1.3", "0x1302", "TLSv13", "TLS_AES_256_GCM_SHA384") == []


def test_different_engine_values_are_conflicts():
    assert engine_conflicts("TLS 1.2", "0xc030", "TLSv13", "TLS_AES_256_GCM_SHA384") == ["TLS_VERSION", "TLS_CIPHER"]
