from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


def test_versioned_and_legacy_liveness_routes_work():
    versioned = client.get("/api/v1/health/live")
    legacy = client.get("/api/health/live")

    assert versioned.status_code == 200
    assert versioned.json() == {"status": "alive"}
    assert versioned.headers["x-api-version"] == "1"
    assert "deprecation" not in versioned.headers
    assert legacy.status_code == 200
    assert legacy.headers["deprecation"] == "true"
    assert legacy.headers["link"] == '</api/v1/health/live>; rel="successor-version"'


def test_openapi_publishes_only_v1_contract():
    paths = client.get("/openapi.json").json()["paths"]

    assert "/api/v1/jobs" in paths
    assert "/api/v1/analyses" in paths
    assert "/api/jobs" not in paths
    assert "/api/analyses" not in paths
