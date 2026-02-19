import re
pat = re.compile(r'\d+')
print(pat.findall('abc123def456'))
