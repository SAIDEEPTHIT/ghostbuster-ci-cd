from pathlib import Path
from ghostbuster.scanners.ai_patterns import AIPatternScanner
from ghostbuster.scanners.dangerous_code import DangerousCodeScanner
from ghostbuster.scanners.secrets import SecretScanner
from ghostbuster.scanners.hallucinated_deps import HallucinatedDependencyScanner
from ghostbuster.engine import GhostBusterEngine, EngineConfig


DEMO = Path(__file__).resolve().parent.parent / "demo_vulnerable"


def test_ai_patterns_detects_placeholder():
    findings = AIPatternScanner().scan(DEMO)
    titles = " ".join(f.title for f in findings)
    assert "AI language model" in titles or "your code here" in titles.lower() or "Sure" in titles


def test_dangerous_code_detects_eval_and_pickle():
    findings = DangerousCodeScanner().scan(DEMO)
    titles = " ".join(f.title for f in findings)
    assert "eval()" in titles
    assert "pickle.loads" in titles
    assert "shell=True" in titles


def test_secrets_detects_hardcoded_keys():
    findings = SecretScanner().scan(DEMO)
    titles = " ".join(f.title for f in findings)
    assert "OpenAI" in titles or "AWS" in titles or "GitHub" in titles


def test_hallucinated_deps_flags_fake_imports():
    s = HallucinatedDependencyScanner(check_pypi=False)
    findings = s.scan(DEMO)
    names = " ".join(f.title for f in findings)
    assert "openaiwrapper" in names
    assert "ai_security_lib" in names
    assert "reqeusts" in names  # typosquat


def test_engine_fails_on_demo():
    cfg = EngineConfig(target=DEMO, threshold=10, check_pypi=False, enable_security_tools=False)
    res = GhostBusterEngine(cfg).run()
    assert res.verdict == "FAIL"
    assert res.score["score"] > 10
