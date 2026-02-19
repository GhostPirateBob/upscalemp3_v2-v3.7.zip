You are given a Lua script that has been obfuscated. Your task is to remove any obfuscation, making the code readable and clear without altering its functionality.

The file is @stage1.lua

**DO NOT ACTUALLY EXECUTE THE SCRIPT IT IS LIKELY MALWARE**

Carefully analyze the script. Identify confusing or meaningless variable and function names, overly complex expressions, and convoluted code structures that obscure the logic.

Rename variables and functions to meaningful, descriptive names wherever their purpose can be inferred or reasonably deduced.

Simplify expressions and structural constructs to straightforward, idiomatic Lua code while preserving exact behavior.

Reformat the code with proper indentation and spacing for clarity.

Verify thoroughly that the deobfuscated code behaves identically to the original, with no functionality changed or lost.


# Steps

1. Parse the given Lua script and detect all obfuscation patterns such as encoded strings, redundant computations, and opaque constructs.
2. Rename variables and functions to descriptive identifiers based on their context and usage.
3. Unwrap and simplify any encoded strings or obfuscated operators.
4. Rewrite complex or nested statements into clearer, linear code.
5. Reformat the entire script with consistent indentation and spacing.
6. Perform a functional check to ensure the script behaves exactly as before.

# Output Format

Provide the cleaned, deobfuscated Lua script as @stage2.lua
The output should be syntactically correct, well-formatted, and easy to read, with meaningful naming but preserving the original logic and behavior exactly.

# Notes

- Do not add any new functionality or remove existing ones.
- Preserve all comments if any, except those containing only obfuscation artifacts.
- Ensure strings and literals remain intact unless they are encoded or obfuscated and can be safely decoded to their original readable form.
- Avoid altering the program’s logic flow.

