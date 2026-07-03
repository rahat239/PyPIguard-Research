"""
AST-based feature extraction, addressing the static-regex limitation identified
in the adversarial evasion experiment. Unlike regex, this parses actual Python
syntax and can resolve simple constant-folding tricks (e.g. 'ev'+'al' -> 'eval')
used to evade literal string matching.
"""
import ast
import math
from collections import Counter

DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__", "execfile"}
DANGEROUS_ATTR_TARGETS = {"eval", "exec", "system", "popen", "spawn", "loads"}
DANGEROUS_MODULE_TARGETS = {"os", "subprocess", "ctypes"}

def try_fold_constant_string(node):
    """Resolve simple string constant-folding (e.g. 'ev' + 'al') to catch
    evasion tricks that break literal regex matching but not AST analysis."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = try_fold_constant_string(node.left)
        right = try_fold_constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None

def shannon_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def extract_ast_features(py_content):
    feats = {
        "ast_parse_success": 0,
        "ast_num_dangerous_builtin_calls": 0,
        "ast_num_getattr_obfuscation": 0,
        "ast_num_dynamic_calls": 0,
        "ast_num_imports": 0,
        "ast_num_high_entropy_strings": 0,
        "ast_max_string_entropy": 0.0,
        "ast_num_functions": 0,
        "ast_max_nesting_depth": 0,
    }

    try:
        tree = ast.parse(py_content)
    except (SyntaxError, ValueError):
        return feats  # ast_parse_success stays 0 -- itself a signal (obfuscated/broken code)

    feats["ast_parse_success"] = 1
    max_entropy = 0.0
    high_entropy_count = 0

    def get_depth(node, depth=0):
        max_d = depth
        for child in ast.iter_child_nodes(node):
            max_d = max(max_d, get_depth(child, depth + 1))
        return max_d

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Direct dangerous builtin call: eval(...), exec(...), etc.
            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
                feats["ast_num_dangerous_builtin_calls"] += 1

            # getattr(X, 'eval') or getattr(X, 'ev'+'al') obfuscation pattern
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                resolved = try_fold_constant_string(node.args[1])
                if resolved and any(target in resolved for target in DANGEROUS_ATTR_TARGETS):
                    feats["ast_num_getattr_obfuscation"] += 1

            # Dynamic call target (not a simple name/attribute) -- e.g. calling
            # the result of another call or a subscript, common in obfuscated code
            if not isinstance(node.func, (ast.Name, ast.Attribute)):
                feats["ast_num_dynamic_calls"] += 1

            # __import__('os').system(...) redirection pattern -- calling a
            # method on the result of a dynamic __import__() call
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                inner_call = node.func.value
                if isinstance(inner_call.func, ast.Name) and inner_call.func.id == "__import__" and inner_call.args:
                    resolved_module = try_fold_constant_string(inner_call.args[0])
                    if resolved_module in DANGEROUS_MODULE_TARGETS:
                        feats["ast_num_getattr_obfuscation"] += 1

        if isinstance(node, (ast.Import, ast.ImportFrom)):
            feats["ast_num_imports"] += 1

        if isinstance(node, ast.FunctionDef):
            feats["ast_num_functions"] += 1

        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 40:
            ent = shannon_entropy(node.value)
            max_entropy = max(max_entropy, ent)
            if ent > 4.0:
                high_entropy_count += 1

    feats["ast_num_high_entropy_strings"] = high_entropy_count
    feats["ast_max_string_entropy"] = round(max_entropy, 3)
    try:
        feats["ast_max_nesting_depth"] = get_depth(tree)
    except RecursionError:
        feats["ast_max_nesting_depth"] = -1

    return feats


if __name__ == "__main__":
    # Self-test against the exact evasion trick from our earlier experiment
    evaded_code = "getattr(__builtins__, 'ev'+'al')(user_input)"
    result = extract_ast_features(evaded_code)
    print("AST features for the evasion-trick code:")
    for k, v in result.items():
        print(f"  {k}: {v}")
    assert result["ast_num_getattr_obfuscation"] == 1, "AST should catch the getattr obfuscation trick!"
    print("\nSelf-test passed: AST correctly caught the string-concatenation evasion trick.")
