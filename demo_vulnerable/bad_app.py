"""INTENTIONALLY VULNERABLE — do not use in production.

This file is consumed by the GhostBuster demo to trigger pipeline failures.
"""
import os
import pickle
import subprocess

# Hallucinated / non-existent imports (LLMs love to fabricate these):
import openaiwrapper          # noqa: F401  - does not exist on PyPI
import ai_security_lib        # noqa: F401  - hallucinated
import reqeusts               # noqa: F401  - typosquat of 'requests'

# Hardcoded API keys (scanner should flag CRITICAL):
OPENAI_API_KEY = "sk-AbCDefGhIJKlmNoPQRsTUvWxyZ0123456789abcd"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

# AI-assistant boilerplate that should never ship:
# As an AI language model, I cannot guarantee this code is correct.
# Sure, here is the code you asked for:
# ```python
# your code here
# ```


def run_user_command(cmd: str):
    # Critical: shell=True + user input
    subprocess.run(cmd, shell=True)
    os.system(cmd)  # also flagged


def load_session(blob: bytes):
    # Critical: pickle on untrusted input
    return pickle.loads(blob)


def run_expression(expr: str):
    # Critical: eval on user input
    return eval(expr)


def todo_function():
    # TODO: implement
    pass  # placeholder


def unfinished():
    raise NotImplementedError("fill this in later")

# demo trigger
# demo