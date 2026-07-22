"""PyPIGuard: lightweight pre-install static/AST detection of malicious PyPI
packages. This package factors the detection core (feature extraction +
model inference) out of the Flask web app so it can be reused as a library
or a standalone CLI -- e.g. in a CI pipeline, pre-commit hook, or another
tool's dependency-audit step -- without needing to run a web server.

The webapp (webapp/app.py) imports from this package rather than
duplicating the logic; both consumers therefore always test the exact same
detection pipeline used in this project's own evaluation.
"""
__version__ = "1.2.0"
