import sys
with open(r"C:/TEMP/upscalemp3_v2-v3.7/stage1.lua", "r", encoding="utf-8") as f:
    content = f.read()
print("Read", len(content), "chars")
BSL = chr(92)
DQ = chr(34)

# Extract D table
d_sp = content.find('local D={') + len('local D={')
dc = 1
cp = None
for idx in range(d_sp, len(content)):
    if content[idx] == '{': dc += 1
    elif content[idx] == '}':
        dc -= 1
        if dc == 0:
            cp = idx
            break
d_inner = content[d_sp:cp]
print('D inner:', len(d_inner), 'chars')

# Parse entries at top level
entries = []
cur = ''
dc = 0
ins = False
idx = 0
while idx < len(d_inner):
    c = d_inner[idx]
    if ins:
        cur += c
        if c == BSL and idx + 1 < len(d_inner):
            cur += d_inner[idx + 1]
            idx += 2
            continue
        elif c == DQ: ins = False
        idx += 1
        continue
    if c == DQ:
        ins = True
        cur += c
    elif c == '{': dc += 1; cur += c
    elif c == '}': dc -= 1; cur += c
    elif (c == ',' or c == ';') and dc == 0:
        e = cur.strip()
        if e: entries.append(e)
        cur = ''
    else: cur += c
    idx += 1
if cur.strip(): entries.append(cur.strip())
print('Entries:', len(entries))

# Lua string decode
def dls(s):
    r = ''
    i = 0
    while i < len(s):
        if s[i] == BSL and i+1 < len(s) and s[i+1].isdigit():
            d = ''
            j = i + 1
            while j < len(s) and j < i+4 and s[j].isdigit():
                d += s[j]; j += 1
            r += chr(int(d)); i = j
        else: r += s[i]; i += 1
    return r

# Parse Lua table
def pt(s):
    els = []; cur = ''; dp = 0; ist = False; i = 0
    while i < len(s):
        c = s[i]
        if ist:
            cur += c
            if c == BSL and i+1 < len(s):
                cur += s[i+1]; i += 2; continue
            elif c == DQ: ist = False
            i += 1; continue
        if c == DQ: ist = True; cur += c
        elif c == '{': dp += 1; cur += c
        elif c == '}': dp -= 1; cur += c
        elif (c == ',' or c == ';') and dp == 0:
            e = cur.strip()
            if e: els.append(e)
            cur = ''
        else: cur += c
        i += 1
    if cur.strip(): els.append(cur.strip())
    res = []
    for el in els:
        if el.startswith('{') and el.endswith('}'):
            res.append(('t', pt(el[1:-1])))
        elif el.startswith(DQ) and el.endswith(DQ):
            res.append(('s', dls(el[1:-1])))
        else:
            try: res.append(('n', int(el)))
            except: res.append(('u', el))
    return res

# z() decoder
def dz(tc):
    el = pt(tc); n = len(el); h = n//2
    ix = [el[i][1] for i in range(h)]
    st = [el[i][1] for i in range(h, n)]
    return ''.join(st[x-1] for x in ix)

# E() decoder
def de(tc):
    el = pt(tc); n = len(el)
    ss = [item[1] for item in el[n-1][1]]
    return ''.join(ss[el[i][1]-1] for i in range(len(ss)))

# Decode all entries
D = []
errs = 0
for ei, entry in enumerate(entries):
    try:
        if entry.startswith('z({') and entry.endswith('})'):
            D.append(dz(entry[3:-2]))
        elif entry.startswith('E({') and entry.endswith('})'):
            D.append(de(entry[3:-2]))
        elif entry.startswith(DQ) and entry.endswith(DQ):
            D.append(dls(entry[1:-1]))
        else:
            D.append(entry); errs += 1
    except Exception as ex:
        print(f'ERR [{ei+1}]: {ex}')
        D.append('ERROR'); errs += 1
print(f'Decoded {len(D)} entries, {errs} errors')

# Shuffle
def rs(a, s, e):
    s -= 1; e -= 1
    while s < e: a[s],a[e] = a[e],a[s]; s += 1; e -= 1
rs(D, 1, 1072); rs(D, 1, 504); rs(D, 505, 1072)
print('Shuffle done')

b64 = {'3': 63, 'H': 1, '4': 24, '1': 23, '/': 8, 'w': 55, 'Q': 37, 'S': 61, 'z': 48, 'e': 18, 'T': 26, 'Z': 17, 'W': 39, '5': 22, 'm': 44, 'E': 56, 'g': 6, 'i': 7, 's': 29, 'J': 57, 'B': 36, 'L': 28, 'd': 40, 'l': 4, '6': 62, 'n': 13, 'r': 3, 'O': 42, '+': 19, 'c': 51, '8': 35, 'D': 11, 'h': 43, 'P': 49, 'j': 58, 'f': 12, 'X': 31, 'R': 14, 'V': 60, 'x': 27, 'M': 16, 'K': 9, 'b': 46, 'I': 15, 'v': 33, 'G': 47, 'u': 30, 'y': 10, 'C': 38, 'p': 5, '9': 53, 't': 54, 'A': 34, 'q': 0, 'U': 20, 'a': 52, 'N': 45, '2': 21, 'o': 25, 'Y': 2, 'F': 32, '0': 41, 'k': 50, '7': 59}
print(f'B64 map: {len(b64)} entries')

def b64d(s):
    rb = []; t = 0; C = 0
    for i, ch in enumerate(s):
        if ch in b64:
            t += b64[ch] * (64 ** (3-C)); C += 1
            if C == 4:
                C = 0; rb.append(t>>16); rb.append((t>>8)&255); rb.append(t&255); t = 0
        elif ch == '=':
            rb.append(t>>16)
            if i+1 >= len(s) or s[i+1] != '=': rb.append((t>>8)&255)
            break
    return bytes(rb)

dD = []
for v in D:
    try: dD.append(b64d(v).decode('utf-8', errors='replace'))
    except: dD.append(v)
print(f'B64 decoded {len(dD)} entries')
print()

print('=' * 80)
print('FIRST 50 DECODED STRINGS:')
print('=' * 80)
for i in range(50):
    zk = i + 1 + 48459
    s = dD[i]
    disp = repr(s) if any(ord(c)<32 or ord(c)>126 for c in s) else s
    print(f'D[{i+1:4d}] (Z_key={zk}): {disp}')

with open(r"C:/TEMP/upscalemp3_v2-v3.7/string_table.txt", "w", encoding="utf-8") as f:
    for i in range(len(dD)):
        zk = i + 1 + 48459
        f.write(f"D[{i+1:4d}] (Z_key={zk}): {dD[i]}" + chr(10))
print(f"Written {len(dD)} entries to string_table.txt")
