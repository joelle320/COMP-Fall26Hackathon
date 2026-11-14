from pathlib import Path
import re

from fastapi.testclient import TestClient
import pytest

from sentinel.api import create_app


def test_self_hosted_api_reference_is_compatible_with_dashboard_csp(tmp_path):
    with TestClient(create_app(tmp_path, admin_token="local-test-authority")) as client:
        response = client.get("/api/docs")
        assert response.status_code == 200
        assert "cdn.jsdelivr" not in response.text
        sources = re.findall(r'<script src="([^"]+)"', response.text)
        assert len(sources) == 2
        for source in sources:
            assert client.get(source).status_code == 200
        assert "'unsafe-eval'" not in response.headers["content-security-policy"]
        schema = client.get("/api/openapi.json").json()
        assert "/api/gateway/execute" in schema["paths"]


def test_built_dashboard_and_its_entry_assets_are_served_by_python_backend(tmp_path):
    distribution = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if not (distribution / "index.html").is_file():
        pytest.skip("Build frontend with npm ci && npm run build to verify dashboard delivery")
    with TestClient(create_app(tmp_path, admin_token="local-test-authority")) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert 'id="root"' in response.text
        assert client.get("/sentinel.svg").status_code == 200
        assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', response.text)
        assert assets
        for asset in assets:
            response = client.get(asset)
            assert response.status_code == 200, asset
            assert response.content, asset
        assert client.get("/api/state").status_code == 401
