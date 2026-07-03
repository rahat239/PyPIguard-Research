"""
Bytecode-level static analysis -- a deeper layer than AST that inspects
the STRUCTURE of compiled bytecode rather than trying to resolve exact
string values, making it more robust against varied obfuscation techniques
(string concatenation, chr()-building, format strings, etc.) that all
produce the same underlying bytecode SHAPE.

SAFETY NOTE: compile() only compiles source to bytecode -- it NEVER
executes the code. This is a purely static technique despite inspecting
a lower-level representation than the AST.
"""
import dis


def extract_bytecode_features(py_content):
    feats = {
        "bytecode_compile_success": 0,
        "bytecode_getattr_builtins_pattern": 0,
        "bytecode_num_call_ops": 0,
        "bytecode_num_string_build_ops": 0,
    }
    try:
        compiled = compile(py_content, "<module>", "exec")
    except (SyntaxError, ValueError, TypeError):
        return feats

    feats["bytecode_compile_success"] = 1

    def scan(code_obj):
        instructions = list(dis.get_instructions(code_obj))
        names_loaded = []
        for i, instr in enumerate(instructions):
            if instr.opname == "LOAD_NAME" or instr.opname == "LOAD_GLOBAL":
                names_loaded.append((i, instr.argval))
            if instr.opname == "CALL":
                feats["bytecode_num_call_ops"] += 1
            if instr.opname in ("BINARY_OP",) and instr.argval == 0:  # '+' operator
                feats["bytecode_num_string_build_ops"] += 1

        # Detect getattr(...) called with __builtins__/globals()/vars() nearby --
        # this pattern holds regardless of HOW the attribute-name string is built
        loaded_names = {name for _, name in names_loaded}
        if "getattr" in loaded_names and (
            "__builtins__" in loaded_names or "globals" in loaded_names or "vars" in loaded_names
        ):
            feats["bytecode_getattr_builtins_pattern"] = 1

        # Recurse into nested code objects (functions, comprehensions, etc.)
        for const in code_obj.co_consts:
            if hasattr(const, "co_code"):
                scan(const)

    scan(compiled)
    return feats


if __name__ == "__main__":
    # Self-tests against BOTH evasion styles
    test_concat = "getattr(__builtins__, 'ev'+'al')(x)"
    test_chr = "getattr(__builtins__, chr(101)+chr(118)+chr(97)+chr(108))(x)"
    test_clean = "import os\nprint('hello')"

    for name, code in [("string-concat evasion", test_concat), ("chr()-based evasion", test_chr), ("clean code", test_clean)]:
        result = extract_bytecode_features(code)
        print(f"{name}: getattr_builtins_pattern = {result['bytecode_getattr_builtins_pattern']}")
