# SmartLoader Malware Analysis: `upscalemp3_v2-v3.7`

Analysis of a **SmartLoader** malware sample disguised as an audio processing tool. The payload is a LuaJIT-based loader protected by the **Luraph** commercial bytecode virtualizer, using **EtherHiding** (blockchain smart contract) for C2 configuration and **Yandex Cloud CDN** for command-and-control infrastructure.

> **Campaign status:** Dead... or just good at hiding from sandboxes... Blockchain RPC API key revoked; C2 backend still alive behind Yandex.

## Sample Origin

| | |
|---|---|
| **Source repo** | `https://github.com/Fewy45/upscalemp3_v2` (malicious, not taken down as of yet) |
| **Direct download** | `https://raw.githubusercontent.com/Fewy45/upscalemp3_v2/main/src/upscalemp3_v2-v3.7.zip` |
| **Archive** | [`upscalemp3_v2-v3.7.zip`](upscalemp3_v2-v3.7.zip) (password: `infected`) |
| **Family** | SmartLoader (LuaJIT-based malware loader) |
| **Obfuscator** | Luraph (commercial Lua bytecode virtualizer) |
| **C2 technique** | EtherHiding + Yandex Cloud CDN abuse |
| **Expected payloads** | Lumma Stealer, Redline Stealer, Rhadamanthys |

## Key Findings

Read the full report: **[`threat-assessment.md`](threat-assessment.md)**

- 4-file package: LuaJIT exe + lua51.dll + obfuscated Lua script (`clib.txt`) + batch launcher
- Payload protected by Luraph VM with 546 dispatch states, custom base64, anti-tamper via pcall line-number validation
- Two-stage C2: blockchain `getData()` retrieves routing config, then connects to Yandex L7 balancer at `80.253.249.107`
- Contract address: `0x1823A9a0Ec8e0C25dD957D0841e3D41a4474bAdc` (likely Polygon chain)
- C2 IP serves valid `*.yandex.tr` certificate (real Yandex infrastructure, not spoofed)

## Repository Structure

Folders are numbered to reflect the chronological analysis workflow:

```
upscalemp3_v2-v3.7/
|
+-- threat-assessment.md          # Full threat assessment report with IOCs, MITRE mapping,
|                                   annotated code, kill chain, and threat actor profile
|
+-- upscalemp3_v2-v3.7.zip        # Original malware ZIP (password: infected)
|
+-- 00-original/                   # Original malware files (DEFANGED - .exe/.cmd renamed)
|   +-- Launcher.cmdx              #   Batch launcher (originally .cmd) - "start luajit.exe clib.txt"
|   +-- luajit.exex                #   LuaJIT interpreter (originally .exe)
|   +-- lua51.dll                  #   LuaJIT runtime library
|   +-- clib.og.txt                #   Original obfuscated payload (355,768 bytes, single line)
|   +-- clib.lua.txt               #   Same file, Lua-identified copy
|
+-- 01-obfuscated/                 # Formatted obfuscated code
|   +-- stage1.lua                 #   clib.txt after stylua formatting (20,078 lines)
|   +-- stage1_formatted.lua       #   Alternative formatting pass
|   +-- example.lua                #   Reference Luraph-obfuscated example for comparison
|
+-- 02-decomposed/                 # Manually split sections of stage1.lua
|   +-- part1_helpers.lua          #   String decoder functions E() and z()
|   +-- part2_data.lua             #   String table D (1,072 entries)
|   +-- part3_vm.lua               #   VM interpreter (~13K lines, 546 states)
|   +-- part3_formatted.lua        #   Formatting attempt on VM section
|
+-- 03-string-decode/              # String table decoding
|   +-- decode_strings.py          #   Initial decoder script
|   +-- decode2.py                 #   Iterative decoder improvements
|   +-- decode3.py                 #   Batch decoding with custom base64 alphabet
|   +-- decode4.py                 #   Final decoder with full table output
|   +-- string_table.txt           #   All 1,072 decoded entries (186 ASCII, 886 binary)
|
+-- 04-vm-analysis/                # VM structure analysis
|   +-- analyze_vm.py              #   VM handler extraction script
|   +-- vm_handlers_raw.json       #   All 546 dispatch states as JSON
|   +-- vm_tokens.json             #   Tokenized VM operations
|   +-- bootstrap.py               #   VM bootstrap/entry point analysis
|   +-- gen.py                     #   Code generation utilities
|   +-- write_script.py            #   Script writer for analysis output
|   +-- test_regex.py              #   Pattern matching tests for VM parsing
|   +-- script_b64.txt             #   Base64-encoded analysis scripts
|
+-- 05-deobfuscated/               # Deobfuscation output
|   +-- sad.txt                    #   "Yeah I gave up on full deobfuscating this" :)
|
+-- packets/                       # Network packet captures
|   +-- out.pcapng                 #   Full packet capture from malware execution
|   +-- marked.pcap                #   Filtered/marked capture
|   +-- 80.253.249.107.pcap        #   C2 IP traffic only
|   +-- packets.txt                #   Wireshark dissection (9 packets, all unanswered SYNs)
|   +-- first-5-packets.md         #   Annotated first 5 packets with hex dumps
|
+-- .notes/                        # Research notes and working files
|   +-- curl.log                   #   curl response from C2 IP (HTTP 406, Yandex headers)
|   +-- openssl.log                #   TLS certificate chain for C2 IP (*.yandex.tr)
|   +-- chat01.md                  #   Early analysis chat with another AI agent
|   +-- claude.md                  #   Intermediate analysis notes
|   +-- prompt.md                  #   Original analysis prompts
|   +-- prompt2.md                 #   Follow-up prompts
|   +-- anyrun-report.html         #   Saved any.run sandbox report
|   +-- anyrun-report/             #   any.run report assets (screenshots, CSS, JS)
|   +-- anyrun-report-01.png       #   Sandbox screenshot 1
|   +-- anyrun-report-02.png       #   Sandbox screenshot 2
|
+-- .stylua.toml                   # stylua formatter config
+-- .gitattributes                 # Git LFS / line ending config
```

## Analysis Methodology

This analysis was performed collaboratively between a human analyst and Claude (Anthropic's AI), across multiple sessions. The work progressed through:

1. **Structural decomposition** -- Splitting the single-line 355KB payload into logical sections
2. **String table decoding** -- Custom base64 alphabet identification and full decode of 1,072 entries
3. **VM architecture mapping** -- Identifying Luraph's binary search dispatch, 18 helpers, 76 registers
4. **Sandbox correlation** -- Matching any.run behavioral data with static analysis findings
5. **Infrastructure investigation** -- TLS cert analysis, curl probing, Wireshark packet capture
6. **Blockchain C2 identification** -- EtherHiding technique, `getData()` function selector, contract address
7. **Yandex CDN discovery** -- Proving the C2 IP is real Yandex infrastructure via response headers

Full conversation transcripts from the analysis sessions are in `.notes/conversations/`.

## Safety Notes

- All executable files in `00-original/` have been **defanged** (`.exe` -> `.exex`, `.cmd` -> `.cmdx`)
- The ZIP archive is password-protected with `infected` (standard malware sharing convention)
- **Do not execute** any files from this repository on a non-isolated system
- The C2 backend at `80.253.249.107` is still alive -- do not probe it outside of a controlled environment

## References

See the [References section](threat-assessment.md#11-references) in the threat assessment for full source links covering SmartLoader, Luraph, EtherHiding, and related research.
