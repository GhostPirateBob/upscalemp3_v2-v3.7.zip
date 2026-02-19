import sys, base64
data = sys.stdin.read()
decoded = base64.b64decode(data).decode("utf-8")
with open("analyze_vm.py", "w", encoding="utf-8") as out:
    out.write(decoded)
print(f"Written {len(decoded)} chars to analyze_vm.py")
