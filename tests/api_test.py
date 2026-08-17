from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from modulo2_2.app import create_app


def test_user_order_and_orderitem_crud_with_jwt(tmp_path: Path):
    db_path = tmp_path / "test.db"
    app = create_app(database_url=f"sqlite:///{db_path}")
    client = TestClient(app)

    # Create user
    response = client.post(
        "/users/",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "secret123",
        },
    )
    assert response.status_code == 201, response.text
    user = response.json()
    assert user["username"] == "alice"
    assert "password" not in user

    # Login
    response = client.post(
        "/auth/login",
        data={"username": "alice", "password": "secret123"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    assert token

    headers = {"Authorization": f"Bearer {token}"}

    # List users
    response = client.get("/users/", headers=headers)
    assert response.status_code == 200, response.text
    users = response.json()
    assert any(item["username"] == "alice" for item in users)

    # Create order
    response = client.post(
        "/orders/",
        json={"user_id": user["id"], "status": "pending"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    order = response.json()
    order_id = order["id"]
    assert order["user_id"] == user["id"]

    # Create order item
    response = client.post(
        "/order-items/",
        json={
            "order_id": order_id,
            "product_name": "Laptop",
            "quantity": 2,
            "unit_price": 999.99,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["product_name"] == "Laptop"
    assert item["order_id"] == order_id

    # Read order details and item details
    response = client.get(f"/orders/{order_id}", headers=headers)
    assert response.status_code == 200, response.text
    order_detail = response.json()
    assert order_detail["user_id"] == user["id"]
    assert order_detail["items"][0]["product_name"] == "Laptop"

    response = client.get(f"/order-items/{item['id']}", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["product_name"] == "Laptop"

    # Update order and item
    response = client.put(
        f"/orders/{order_id}",
        json={"user_id": user["id"], "status": "paid"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "paid"

    response = client.put(
        f"/order-items/{item['id']}",
        json={
            "order_id": order_id,
            "product_name": "Mouse",
            "quantity": 3,
            "unit_price": 25.5,
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["product_name"] == "Mouse"

    # Delete order item and order
    response = client.delete(f"/order-items/{item['id']}", headers=headers)
    assert response.status_code == 200, response.text
    response = client.delete(f"/orders/{order_id}", headers=headers)
    assert response.status_code == 200, response.text

    response = client.get(f"/orders/{order_id}", headers=headers)
    assert response.status_code == 404
