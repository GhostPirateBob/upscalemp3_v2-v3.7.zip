import re

f = open('C:\\TEMP\\upscalemp3_v2-v3.7\\stage1.lua', 'r')
d = f.read()
f.close()

all_quoted = re.findall('"([^"]+)"', d)
print('Total quoted string literals:', len(all_quoted))
print()

decoded_all = []
bspat = '\\\\(\\d{3})'
pat = re.compile(bspat)
for qs in all_quoted:
    nums = pat.findall(qs)
    if nums:
        decoded = "".join(chr(int(n)) for n in nums)
        decoded_all.append(decoded)

print('Decoded strings:', len(decoded_all))
seen = list()
for decoded in decoded_all:
    if decoded not in seen:
        seen.append(decoded)
print('Unique decoded strings:', len(seen))
print()
for s in sorted(seen):
    print( '  ', repr(s))
