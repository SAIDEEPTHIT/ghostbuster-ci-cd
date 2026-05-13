"""Second demo file — weak crypto + insecure tempfile + unsafe yaml."""
import hashlib
import tempfile
import yaml  # noqa: F401


def fingerprint(data: bytes) -> str:
    # MD5 + SHA1 are broken
    return hashlib.md5(data).hexdigest() + hashlib.sha1(data).hexdigest()


def make_tmp() -> str:
    # mktemp is race-prone
    return tempfile.mktemp(suffix=".cache")


def load_config(text: str):
    # yaml.load without SafeLoader
    return yaml.load(text)
