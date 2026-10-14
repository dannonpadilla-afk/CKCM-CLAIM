import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lostfound"))

from app import add_user, USERS, find_user_by_name


def setup_module():
    USERS.clear()
    add_user("admin", "admin", "admin123", "Admin User")
    add_user("student", "student", "student123", "Student User")


def test_deactivated_user_cannot_log_in():
    user = find_user_by_name("student")
    user.deactivate()

    from app import app
    client = app.test_client()
    resp = client.post("/login", data={"username": "student", "password": "student123"}, follow_redirects=True)

    assert resp.status_code == 200
    assert b"This account has been deactivated" in resp.data


def test_admin_can_toggle_account_status():
    from app import app
    admin = find_user_by_name("admin")
    student = find_user_by_name("student")
    student.activate()

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["uid"] = admin.id

    resp = client.post(f"/users/{student.id}/toggle-status", follow_redirects=True)
    assert resp.status_code == 200
    assert student.is_active is False

    resp = client.post(f"/users/{student.id}/toggle-status", follow_redirects=True)
    assert resp.status_code == 200
    assert student.is_active is True
