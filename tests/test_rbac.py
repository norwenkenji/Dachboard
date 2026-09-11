from app.rbac import ADMIN_ONLY, RIGHTS, can, default_rights


def test_admin_gets_everything():
    u = {"is_admin": True, "rights": {}}
    for r in RIGHTS:
        assert can(u, r)


def test_default_user_overview_only():
    u = {"is_admin": False, "rights": default_rights()}
    assert can(u, "overview")
    assert not can(u, "terminal")
    assert not can(u, "users_manage")


def test_admin_only_never_for_users():
    u = {"is_admin": False, "rights": {r: True for r in RIGHTS}}
    for r in ADMIN_ONLY:
        assert not can(u, r)


def test_unknown_right_denied():
    assert not can({"is_admin": False, "rights": {}}, "nope")
    assert not can({"is_admin": False, "rights": {}}, "")


def test_missing_rights_key():
    assert not can({"is_admin": False}, "files")
