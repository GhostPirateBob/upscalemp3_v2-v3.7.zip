# Generator script
import os
os.chdir(os.path.join("C:", os.sep, "TEMP", "upscalemp3_v2-v3.7"))
with open("analyze_vm.py", "wb") as out:
    import base64
    data = open("script_b64.txt", "rb").read()
    out.write(base64.b64decode(data))
    print(f"Written {out.tell()} bytes")
