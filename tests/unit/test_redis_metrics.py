from aegis.core.redis_metrics import RedisTopologyStatus, status_to_prometheus

def test_prometheus_text_contains_sentinel_gauges():
    st = RedisTopologyStatus(mode="sentinel", connected=0, configured_sentinels=3, reachable_sentinels=0, last_check_ts=1700000000)
    text = status_to_prometheus(st)
    assert "aegis_redis_sentinel_configured 3" in text
    assert 'aegis_redis_connected{mode="sentinel"} 0' in text

def test_as_dict_shape():
    d = RedisTopologyStatus(mode="standalone", connected=1, backend="redis").as_dict()
    assert d["connected"] is True
