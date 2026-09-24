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
    u = {"is_admin": False, "rights": dict.fromkeys(RIGHTS, True)}
    for r in ADMIN_ONLY:
        assert not can(u, r)


def test_systemd_rights_are_admin_only():
    """Host systemctl runs as root, so it must never be a delegable checkbox."""
    assert {"services_view", "services_control"} <= ADMIN_ONLY
    # ...and a machine token cannot be minted with them either
    from app.rbac import TOKEN_HOLDABLE
    assert not ({"services_view", "services_control"} & TOKEN_HOLDABLE)
    tok = {"is_admin": False, "via": "token",
           "rights": {"services_view": True, "services_control": True}}
    assert not can(tok, "services_view")
    assert not can(tok, "services_control")


def test_container_rights_are_delegable():
    """The delegable half of the old containers_* split must still work."""
    u = {"is_admin": False,
         "rights": {"containers_view": True, "containers_control": True}}
    assert can(u, "containers_view")
    assert can(u, "containers_control")
    assert not can(u, "services_control")


def test_unknown_right_denied():
    assert not can({"is_admin": False, "rights": {}}, "nope")
    assert not can({"is_admin": False, "rights": {}}, "")


def test_missing_rights_key():
    assert not can({"is_admin": False}, "files")
