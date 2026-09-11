import sys

from app import runner as R


def test_echo_self():
    code, out = R.run_as([sys.executable, "-c", "print('hi')"], None, timeout=20)
    assert code == 0
    assert "hi" in out


def test_bad_argv():
    assert R.run_as([], None)[0] == 1
    assert R.run_as(["echo", 123], None)[0] == 1
    assert R.run_as("echo hi", None)[0] == 1


def test_timeout():
    code, out = R.run_as(
        [sys.executable, "-c", "import time; time.sleep(30)"], None, timeout=2)
    assert code == 124
    assert "timeout" in out


def test_nonzero_passthrough():
    code, _ = R.run_as(
        [sys.executable, "-c", "import sys; sys.exit(7)"], None, timeout=20)
    assert code == 7


def test_output_capped():
    code, out = R.run_as(
        [sys.executable, "-c", "print('x' * 200000)"], None, timeout=20)
    assert code == 0
    assert len(out) <= R.MAX_OUTPUT


def test_user_exists():
    assert not R.user_exists("definitely-not-a-user-xyz")
    try:
        import pwd  # noqa
    except ImportError:
        return
    import getpass
    assert R.user_exists(getpass.getuser())
