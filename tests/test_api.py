import time

from fastapi.testclient import TestClient

from digiscope.app import app


def test_meta_detect_and_network_free_scan_exports():
    with TestClient(app) as client:
        meta = client.get("/api/meta")
        assert meta.status_code == 200
        body = meta.json()
        assert body["name"] == "DigiScope"
        assert {item["key"] for item in body["modules"]} >= {"domain", "ip", "email", "username", "phone", "person", "url", "hash", "crypto"}

        detected = client.get("/api/detect", params={"q": "person@example.org"})
        assert detected.status_code == 200
        assert detected.json()["type"] == "email"

        created = client.post("/api/scan", json={"input": "Ada Lovelace", "type": "auto", "options": {"modules": []}})
        assert created.status_code == 202
        job_id = created.json()["id"]

        payload = None
        for _ in range(30):
            response = client.get(f"/api/scan/{job_id}")
            assert response.status_code == 200
            payload = response.json()
            if payload["status"] in {"complete", "error"}:
                break
            time.sleep(0.03)
        assert payload["status"] == "complete"
        assert payload["exposure_score"] == 0
        assert payload["options"]["safe_mode"] is True

        for format_name in ("json", "csv", "md", "html"):
            exported = client.get(f"/api/scan/{job_id}/export", params={"format": format_name})
            assert exported.status_code == 200
            assert len(exported.content) > 20
            assert "attachment" in exported.headers.get("content-disposition", "")


def test_validation_and_health():
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.post("/api/scan", json={"input": "example.org", "type": "not-a-type"}).status_code == 422
        assert client.get("/api/scan/not-real").status_code == 404
