import re, os

filepath = os.path.join('C:', os.sep, 'TEMP', 'upscalemp3_v2-v3.7', 'stage1.lua')
f = open(filepath, 'r')
d = f.read()
f.close()

# Find all quoted strings
all_quoted = re.findall('"([^"]+)"', d)
print('Total quoted string literals:', len(all_quoted))

decoded_all = []
# Use string splitting approach instead of regex to avoid backslash issues
for qs in all_quoted:
    if chr(92) not in qs:
        continue
    parts = qs.split(chr(92))
    nums = []
    for p in parts:
        if len(p) >= 3 and p[:3].isdigit():
            nums.append(int(p[:3]))
    if nums:
        decoded = ''.join(chr(n) for n in nums if 0 <= n <= 127)
        decoded_all.append(decoded)

print('Decoded strings:', len(decoded_all))
seen = list()
for decoded in decoded_all:
    if decoded not in seen:
        seen.append(decoded)
print('Unique decoded strings:', len(seen))
print()
for s in sorted(seen):
    print('  ', repr(s))

print()
print('=== Strings possibly containing URLs/domains ===')
for s in sorted(seen):
    sl = s.lower()
    if any(x in sl for x in ['http', 'www', '.com', '.net', '.org', '.io', '.gg', 'discord', 'pastebin', 'github', 'raw.', '://', '.lua', '.exe', '.dll', '.bat', '.cmd', '.ps1', 'load', 'string', 'require', 'game', 'script']):
        print('  INTERESTING:', repr(s))
