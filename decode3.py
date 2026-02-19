import re, os

filepath = os.path.join('C:', os.sep, 'TEMP', 'upscalemp3_v2-v3.7', 'stage1.lua')
f = open(filepath, 'r')
d = f.read()
f.close()

all_quoted = re.findall('"([^"]+)"', d)
print('Total quoted string literals:', len(all_quoted))
print()

decoded_all = []
# Pattern: two literal backslashes followed by 3 digits
bspat = re.compile(chr(92) * 2 + '(' + chr(92) + 'd{3})')
for qs in all_quoted:
    nums = bspat.findall(qs)
    if nums:
        decoded = ''.join(chr(int(n)) for n in nums)
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
