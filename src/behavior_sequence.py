"""
A behavior-sequence extractor inspired by Cerebro's core idea (Zhang et al.,
ACM TOSEM): representing a package's maliciousness as an ORDERED sequence of
behavioral operations, rather than a flat feature vector.

IMPORTANT HONESTY NOTE: this is a simplified proxy, not a reproduction of
Cerebro. Cerebro uses call-graph traversal across install/import/runtime
phases and fine-tunes a pre-trained BERT model on the resulting sequence.
This proxy instead walks the AST in source order and classifies with
TF-IDF + Logistic Regression, since no pre-trained-LM fine-tuning
infrastructure is available in this environment. It captures the core
"sequence, not just presence" idea for a fair, honestly-labeled comparison.
"""
import ast

OPERATION_TOKENS = {
    "eval": "OP_EVAL", "exec": "OP_EXEC", "compile": "OP_COMPILE",
    "__import__": "OP_DYNAMIC_IMPORT", "system": "OP_OS_SYSTEM",
    "popen": "OP_POPEN", "Popen": "OP_SUBPROCESS", "call": "OP_SUBPROC_CALL",
    "run": "OP_SUBPROC_RUN", "b64decode": "OP_BASE64_DECODE",
    "socket": "OP_SOCKET", "urlopen": "OP_URLOPEN", "get": "OP_HTTP_GET",
    "post": "OP_HTTP_POST", "environ": "OP_ENV_ACCESS", "getattr": "OP_GETATTR",
    "loads": "OP_DESERIALIZE",
}


def extract_behavior_sequence(py_content):
    """Returns a space-separated string of behavior tokens in source order --
    a textual 'sentence' representing the package's behavior sequence."""
    try:
        tree = ast.parse(py_content)
    except (SyntaxError, ValueError):
        return "OP_PARSE_FAILED"

    sequence = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                sequence.append(f"IMPORT_{alias.name.upper()}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            sequence.append(f"IMPORT_{node.module.upper()}")
        elif isinstance(node, ast.Call):
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name and name in OPERATION_TOKENS:
                sequence.append(OPERATION_TOKENS[name])

    return " ".join(sequence) if sequence else "OP_NONE"
