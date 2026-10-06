"""
Integration tests for NetSentinel AI FastAPI Endpoints
"""

import io
import pytest


def test_home_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "NetSentinel AI" in data["application"]


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "learned_mappings" in data


def test_model_endpoint(client):
    response = client.get("/model")
    assert response.status_code == 200
    data = response.json()
    assert "categories" in data
    assert "parameters" in data
    assert len(data["parameters"]) > 10


def test_analyze_endpoint(client, cisco_config):
    file_payload = {"file": ("cisco_test.txt", io.BytesIO(cisco_config.encode("utf-8")), "text/plain")}
    data_payload = {"framework": "CIS"}

    response = client.post("/analyze", files=file_payload, data=data_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["device"] == "cisco_test.txt"
    assert data["vendor"] == "Cisco"
    assert data["framework"] == "CIS"
    assert "security_score" in data
    assert "compliance_summary" in data
    assert "findings" in data


def test_train_and_learned_endpoints(client):
    train_payload = {
        "command": "custom-rule-api-test-cmd",
        "category": "secure_remote_administration",
        "parameter": "ssh_version",
        "value": "2",
        "severity": "HIGH",
    }

    train_response = client.post("/train", data=train_payload)
    assert train_response.status_code == 200
    train_data = train_response.json()
    assert train_data["success"] is True

    learned_response = client.get("/learned")
    assert learned_response.status_code == 200
    learned_data = learned_response.json()
    assert learned_data["count"] >= 1

    stats_response = client.get("/learning/stats")
    assert stats_response.status_code == 200
    stats_data = stats_response.json()
    assert stats_data["total"] >= 1


def test_report_endpoint(client, cisco_config):
    file_payload = {"file": ("cisco_test.txt", io.BytesIO(cisco_config.encode("utf-8")), "text/plain")}
    data_payload = {"framework": "CIS"}

    response = client.post("/report", files=file_payload, data=data_payload)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert len(response.content) > 1000
    assert response.content[:5] == b"%PDF-"
