# SmartLoader / Luraph Threat Assessment

> **Sample:** `upscalemp3_v2-v3.7`
> **Family:** SmartLoader (LuaJIT-based malware loader)
> **Obfuscator:** Luraph (commercial Lua bytecode virtualizer, active since 2017)
> **Campaign Status:** Infrastructure partially burned -- blockchain RPC key revoked, C2 backend still alive behind Yandex Cloud CDN
> **Date of Analysis:** 2026-02-19

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Sample Composition](#2-sample-composition)
- [3. Obfuscation Analysis (Luraph VM)](#3-obfuscation-analysis-luraph-vm)
- [4. Deobfuscated Code (Annotated)](#4-deobfuscated-code-annotated)
- [5. Behavioral Analysis (any.run Sandbox)](#5-behavioral-analysis-anyrun-sandbox)
- [6. C2 Infrastructure](#6-c2-infrastructure)
- [7. Kill Chain Reconstruction](#7-kill-chain-reconstruction)
- [8. String Table Analysis](#8-string-table-analysis)
- [9. Indicators of Compromise (IOCs)](#9-indicators-of-compromise-iocs)
- [10. MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
- [11. References](#11-references)
- [12. The Story Behind the Code](#12-the-story-behind-the-code)

---

## 1. Executive Summary

This sample is a **SmartLoader** malware dropper disguised as an audio processing tool (`upscalemp3_v2-v3.7`). It uses a **LuaJIT runtime** to execute a heavily obfuscated Lua script protected by the **Luraph** commercial bytecode virtualizer.

The malware implements a **two-stage C2 resolution** architecture:
1. **EtherHiding** -- Retrieves C2 routing configuration from a blockchain smart contract via `getData()` JSON-RPC call
2. **Yandex Cloud CDN abuse** -- Routes C2 traffic through legitimate Yandex infrastructure at `80.253.249.107`

The campaign is **partially dead**: the blockchain RPC API key has been revoked by the provider, breaking the first stage of C2 resolution. However, the Yandex-hosted backend at `80.253.249.107` remains operational (responds HTTP 406 to requests lacking the correct routing headers).

When fully operational, SmartLoader downloads secondary payloads -- typically **Lumma Stealer**, **Redline Stealer**, or **Rhadamanthys** -- which harvest browser credentials, cryptocurrency wallets, and screenshots.

---

## 2. Sample Composition

### File Inventory

| File | Size | Purpose | Notes |
|------|------|---------|-------|
| `Launcher.cmd` | 21 bytes | Batch launcher | Contains `start luajit.exe clib.txt`. *(Defanged to `.cmdx` in our archive.)* |
| `luajit.exe` | ~89 KB | LuaJIT interpreter | Legitimate LuaJIT binary. *(Defanged to `.exex` in our archive.)* |
| `lua51.dll` | ~592 KB | LuaJIT runtime library | Legitimate DLL required by luajit. |
| `clib.txt` | 355,768 bytes | Obfuscated Lua payload | Luraph-protected script. Single line, no whitespace. Extension disguised as `.txt`. |

### Execution Chain

```
Launcher.cmd
    └─> start luajit.exe clib.txt
            └─> LuaJIT loads lua51.dll
                    └─> Executes clib.txt as Lua source
                            └─> Luraph VM initializes
                                    └─> Malware logic runs inside custom VM
```

### File Identification

This matches the **exact SmartLoader package structure** documented by [SecurityBlue](https://www.securityblue.team/blog/posts/jit-happens-exposing-luajit-malware-in-the-wild) and [Intellibron](https://blog.intellibron.io/lua-jit-smartloader-analyzing-the-github-campaign-delivering-stealer/):

| Known SmartLoader | This Sample | Match |
|---|---|---|
| `compiler.exe` / `lua.exe` | `luajit.exe` | LuaJIT interpreter |
| `lua51.dll` | `lua51.dll` | LuaJIT runtime (identical purpose) |
| `conf.txt` / `import.ui` | `clib.txt` | Obfuscated Lua payload |
| `Launch.bat` / `Launcher.bat` | `Launcher.cmd` | Batch trigger |

---

## 3. Obfuscation Analysis (Luraph VM)

### Obfuscator Identification

The payload is protected by **[Luraph](https://lura.ph/)**, a commercial Lua obfuscator active since 2017. Some SmartLoader reports attribute the obfuscation to Prometheus, but this sample is definitively Luraph based on:

| Feature | This Sample | Luraph Signature |
|---|---|---|
| Dispatch mechanism | Binary search `if z < THRESHOLD` tree | Luraph's known dispatch pattern |
| Helper count | 18 internal functions | Matches Luraph architecture |
| Upvalue management | `newproxy` + `__gc` reference counting | Luraph-specific technique |
| String encoding | Custom base64 alphabet + character-reorder decoders | Luraph's string obfuscation |
| Anti-tamper | `error("Tamper Detected!")` via pcall line-number validation | Documented Luraph anti-format protection |
| Line-number extraction | `:(%d*):` pattern in string table | Luraph's stack trace parsing pattern |

### VM Architecture

The 355,768-character single-line script has this structure:

```
Outer wrapper: return (function(...) ... end)(...)
│
├── [Chars 0-183]       String decode helpers E() and z()
│                         E(): Character reorder by index array
│                         z(): Half-table index + string reassembly
│
├── [Chars 183-141,432] Data table D -- 1,072 encoded string entries
│                         Built using E() and z() with Lua decimal escapes (\DDD)
│
├── [Chars 141,432-141,512] Table shuffle
│                         Reverses D[1..1072], D[1..504], D[505..1072]
│
├── [Chars ~141,512-141,555] Index accessor
│                         local function Z(n) return D[n - 48459] end
│                         Maps keys 48460-49531 to D[1]-D[1072]
│
├── [Chars ~141,555-142,596] Base64 decoder
│                         Custom alphabet: qHYrlpgi/KyDfnRIMZe+U2514oTxLsuXFvA8BQCWd0OhmNbGzPkca9twEJj7VS63
│                         Decodes all string entries in D[] in-place
│
├── [Chars 142,596-355,654] VM interpreter function (211K chars, ~60% of file)
│   │
│   ├── 25 parameters (env, unpack, newproxy, setmetatable, getmetatable, select, varargs, + 18 nil slots)
│   ├── 18 helper assignments (call wrappers, ref counting, stack allocation, VM dispatcher)
│   ├── Main VM function with 76 register variables
│   ├── 546 dispatch states in binary search tree
│   └── Entry point: state 4,682,351
│
└── [Chars 355,654-355,768] Final invocation
          return (n(4682351, {}))(unpack(varargs))
          Wraps in: (getfenv() or _ENV, unpack, newproxy, setmetatable, getmetatable, select, {...})
```

### VM Statistics

| Metric | Value |
|---|---|
| Total file size | 355,768 characters (1 line) |
| Formatted size | 613,089 characters (20,078 lines) |
| VM dispatch states | 546 |
| Binary search comparisons | 545 `if z < THRESHOLD` nodes |
| String table entries | 1,072 (186 readable ASCII, 886 binary/bytecode) |
| Register variables | 76 |
| Closure definitions | 45 functions |
| Helper functions | 18 (call wrappers, ref counting, GC, stack management) |
| Bracket balance | Perfect: 9,009 `()`; 1,048 `{}`; 7,077 `[]` |

### Anti-Tamper Mechanism

Luraph's anti-tamper works by exploiting Lua's error reporting:

1. The script deliberately calls `pcall` on code that will error
2. It extracts the **line number** from the error message using the `:(%d*):` pattern
3. Multiple checks compare line numbers from different points in the code
4. If any reformatting changed the line structure (the original is a single line), the numbers won't match
5. Triggers `error("Tamper Detected!")` and halts execution

This is why the original `clib.txt` is a **single 355,768-character line** -- any newlines inserted by formatters or editors change Lua's line numbering and trigger the anti-tamper.

**Known bypass** ([TechHog8984](https://gist.github.com/TechHog8984/2e41a77e1d62b5b9d91a5e84274cdf45)): Hook `pcall` and use `gsub` to normalize all line numbers in error messages to a constant value before Luraph's checks see them.

---

## 4. Deobfuscated Code (Annotated)

Full devirtualization of the 546-state VM is beyond static analysis scope. Below is the **maximum deobfuscation achievable** -- the VM framework with all names resolved, arithmetic simplified, and comprehensive annotations.

### 4a. Outer Wrapper and String Decoders

```lua
-- ============================================================================
-- SmartLoader Payload (Luraph-obfuscated)
-- Original file: clib.txt (355,768 bytes, single line)
-- Obfuscator: Luraph (commercial Lua bytecode virtualizer)
-- Target runtime: LuaJIT (lua51.dll)
-- ============================================================================

return (function(...)

    -- ========================================================================
    -- STRING DECODER: Character Reorder
    -- Takes a table where the last element is a character array, and preceding
    -- elements are indices. Reorders characters by index to produce a string.
    -- Example: reorder_chars({2, 1, 3, {"a","b","c"}}) => "bac"
    -- ========================================================================
    local reorder_chars = function(tbl)
        local char_array, result = tbl[#tbl], ""
        for i = 1, #char_array, 1 do
            result = result .. char_array[tbl[i]]
        end
        return result
    end

    -- ========================================================================
    -- STRING DECODER: Half-Table Index Reassembly
    -- Table is split in half: first half = indices, second half = char strings.
    -- Uses indices from first half to pick characters from second half.
    -- Example: half_index_decode({2, 1, "ab", "cd"}) => "cdab"
    -- ========================================================================
    local half_index_decode = function(tbl)
        local result = ""
        for i = 1, #tbl / 2, 1 do
            result = result .. tbl[#tbl / 2 + tbl[i]]
        end
        return result
    end

    -- ========================================================================
    -- STRING TABLE: 1,072 encoded entries
    -- Each entry uses reorder_chars() or half_index_decode() with Lua decimal
    -- escape sequences (\DDD) to build base64-encoded strings.
    -- After base64 decoding, 186 entries are readable ASCII (Lua API names,
    -- error messages, identifiers) and 886 are binary VM bytecode data.
    -- ========================================================================
    local string_table = {
        half_index_decode({1, 2, "\111\049\075\107\120\119\047", "\061"}),
        half_index_decode({1, 3, 2, "\102\074\106\106\113\066\098\110\074",
            "\112\090\118\069\061", "\067\087"}),
        reorder_chars({2, 1, 3, {"\114\051\097\110\107\043\069",
            "\103\074\102\102", "\061"}}),
        -- ... 1,069 more entries ...
        -- Notable decoded values:
        --   D[3]    = "dofile"           D[42]   = "tonumber"
        --   D[119]  = "Tamper Detected!" D[142]  = "main"
        --   D[158]  = "pcall"           D[159]  = "upper"
        --   D[173]  = "read"            D[183]  = "byte"
        --   D[210]  = "currentDllPath"  D[214]  = "__index"
        --   D[252]  = "gmatch"          D[253]  = "__len"
        --   D[270]  = "next"            D[310]  = "value"
        --   D[351]  = "type"            D[382]  = "lower"
        --   D[392]  = "write"           D[405]  = "require"
        --   D[505]  = "error"           D[511]  = "load"
        --   D[538]  = "floor"           D[566]  = "string"
        --   D[595]  = "__gc"            D[615]  = "seek"
        --   D[619]  = "match"           D[632]  = "gsub"
        --   D[634]  = "arg"             D[665]  = "__metatable"
        --   D[672]  = "random"          D[689]  = "io"
        --   D[727]  = "char"            D[760]  = "os"
        --   D[821]  = "table"           D[956]  = "remove"
        --   D[980]  = ":(%d*):"         D[1023] = "debug"
        --   D[1026] = "unpack"          D[1049] = "math"
        --   D[1058] = "close"
    }

    -- ========================================================================
    -- TABLE SHUFFLE: Permutation of string table entries
    -- Three reverse operations that produce the final ordering.
    -- This is part of the obfuscation -- makes static string extraction harder.
    -- ========================================================================
    for _, range in ipairs({{1, 1072}, {1, 504}, {505, 1072}}) do
        while range[1] < range[2] do
            string_table[range[1]], string_table[range[2]],
            range[1], range[2] =
                string_table[range[2]], string_table[range[1]],
                range[1] + 1, range[2] - 1
        end
    end

    -- ========================================================================
    -- STRING TABLE ACCESSOR
    -- Maps external keys (48460-49531) to internal indices (1-1072).
    -- All VM code references strings via lookup(key) calls.
    -- ========================================================================
    local function lookup(key)
        return string_table[key - 48459]
    end

    -- ========================================================================
    -- BASE64 DECODER
    -- Custom alphabet (NOT standard base64):
    --   qHYrlpgi/KyDfnRIMZe+U2514oTxLsuXFvA8BQCWd0OhmNbGzPkca9twEJj7VS63
    -- Decodes all string table entries in-place.
    -- After this, string_table contains the final usable values.
    -- ========================================================================
    do
        local tbl = string_table
        local char_fn = string.char
        local strlen = string.len
        local insert = table.insert
        local b64map = {
            ["3"] = 63, H = 1,  ["4"] = 24, ["1"] = 23, ["/"] = 8,
            w = 55, Q = 37, S = 61, z = 48, e = 18, T = 26, Z = 17,
            W = 39, ["5"] = 22, m = 44, E = 56, g = 6,  i = 7,
            s = 29, J = 57, B = 36, L = 28, d = 40, l = 4,
            ["6"] = 62, n = 13, r = 3,  O = 42, ["+"] = 19, c = 51,
            ["8"] = 35, D = 11, h = 43, P = 49, j = 58, f = 12,
            X = 31, R = 14, V = 60, x = 27, M = 16, K = 9,
            b = 46, I = 15, v = 33, G = 47, u = 30, y = 10,
            C = 38, p = 5,  ["9"] = 53, t = 54, A = 34, q = 0,
            U = 20, a = 52, N = 45, ["2"] = 21, o = 25, Y = 2,
            F = 32, ["0"] = 41, k = 50, ["7"] = 59,
        }
        local substr = string.sub
        local typeof = type
        local concat = table.concat
        local floor = math.floor

        for idx = 1, #tbl, 1 do
            local entry = tbl[idx]
            if typeof(entry) == "string" then
                local len = strlen(entry)
                local decoded = {}
                local pos = 1
                local accumulator = 0
                local count = 0
                while pos <= len do
                    local ch = substr(entry, pos, pos)
                    local value = b64map[ch]
                    if value then
                        accumulator = accumulator + value * 64 ^ (3 - count)
                        count = count + 1
                        if count == 4 then
                            count = 0
                            local b1 = floor(accumulator / 65536)
                            local b2 = floor((accumulator % 65536) / 256)
                            local b3 = accumulator % 256
                            insert(decoded, char_fn(b1, b2, b3))
                            accumulator = 0
                        end
                    elseif ch == "=" then
                        insert(decoded, char_fn(floor(accumulator / 65536)))
                        if pos >= len or substr(entry, pos + 1, pos + 1) ~= "=" then
                            insert(decoded, char_fn(floor((accumulator % 65536) / 256)))
                        end
                        break
                    end
                    pos = pos + 1
                end
                tbl[idx] = concat(decoded)
            end
        end
    end
```

### 4b. VM Interpreter Framework

```lua
    -- ========================================================================
    -- VM INTERPRETER
    -- ========================================================================
    -- Parameters passed from the outer invocation:
    --   env          = getfenv() or _ENV     (global environment table)
    --   unpack_fn    = unpack or table.unpack
    --   newproxy_fn  = newproxy              (creates light userdata with GC)
    --   setmetatable_fn = setmetatable
    --   getmetatable_fn = getmetatable
    --   select_fn    = select
    --   varargs      = {...}                 (script arguments)
    --   [slots 8-25] = nil                   (reserved for helper reassignment)
    -- ========================================================================

    return (function(
        env,              -- _G / global environment
        unpack_fn,        -- unpack / table.unpack
        newproxy_fn,      -- newproxy (Lua 5.1 / LuaJIT)
        setmetatable_fn,  -- setmetatable
        getmetatable_fn,  -- getmetatable
        select_fn,        -- select
        varargs,          -- {...} from outer scope
        -- Slots 8-25: initially nil, reassigned to helpers below
        create_10arg_wrapper, create_4arg_wrapper,
        vm_dispatch, -- THE VM INTERPRETER (helper #12)
        batch_decref,     -- batch reference count decrement
        create_0arg_wrapper, create_5arg_wrapper, create_7arg_wrapper,
        single_decref, create_10arg_wrapper_2,
        create_3arg_wrapper, create_2arg_wrapper,
        create_1arg_wrapper, -- helper #15
        create_varargs_wrapper,
        refcount_table,   -- {} reference count tracking
        refcount_setup,   -- ref-count init + proxy creator
        stack_pointer,    -- 0 (initial stack counter)
        upvalue_store,    -- {} upvalue/closure storage
        create_6arg_wrapper,
        alloc_stack_slot, -- stack allocator
        unused_slot
    )

    -- ====================================================================
    -- HELPER FUNCTION ASSIGNMENTS (18 total)
    -- These are reassigned via multiple-return on the parameter slots.
    -- ====================================================================

    create_6arg_wrapper,        -- #1:  R(state, upvals) -> function(a,b,c,d,e,f)
    create_varargs_wrapper,     -- #2:  n(state, upvals) -> function(...)
    alloc_stack_slot,           -- #3:  N() -> allocates slot, sets refcount=1
    create_4arg_wrapper,        -- #4:  U(state, upvals) -> function(a,b,c,d)
    batch_decref,               -- #5:  C(list) -> decrements refcounts for list
    create_0arg_wrapper,        -- #6:  q(state, upvals) -> function()
    create_5arg_wrapper,        -- #7:  G(state, upvals) -> function(a,b,c,d,e)
    create_7arg_wrapper,        -- #8:  I(state, upvals) -> function(a,b,c,d,e,f,g)
    single_decref,              -- #9:  d(slot) -> decrements single refcount
    create_10arg_wrapper,       -- #10: A(state, upvals) -> function(a..j)
    create_3arg_wrapper,        -- #11: a(state, upvals) -> function(a,b,c)
    vm_dispatch,                -- #12: THE VM DISPATCHER (546 states)
    stack_pointer,              -- #13: i = 0
    upvalue_store,              -- #14: f = {}
    create_1arg_wrapper,        -- #15: V(state, upvals) -> function(a)
    refcount_table,             -- #16: L = {}
    refcount_setup,             -- #17: t(upvals) -> proxy with __gc cleanup
    create_2arg_wrapper         -- #18: y(state, upvals) -> function(a,b)
    =
        -- [Helper #1] 6-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c, d, e, f)
                return vm_dispatch(entry_state, {a, b, c, d, e, f},
                                   upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #2] Varargs closure wrapper (used for entry point)
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(...)
                return vm_dispatch(entry_state, {...}, upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #3] Stack slot allocator
        function()
            stack_pointer = 1 + stack_pointer
            refcount_table[stack_pointer] = 1
            return stack_pointer
        end,

        -- [Helper #4] 4-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c, d)
                return vm_dispatch(entry_state, {a, b, c, d},
                                   upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #5] Batch reference count decrement
        -- Walks a linked list of upvalue slots, decrementing refcounts.
        -- When refcount hits 0, cleans up the slot.
        function(list)
            local idx, slot = 1, list[1]
            while slot do
                refcount_table[slot] = refcount_table[slot] - 1
                idx = 1 + idx
                if 0 == refcount_table[slot] then
                    refcount_table[slot], upvalue_store[slot] = nil, nil
                end
                slot = list[idx]
            end
        end,

        -- [Helper #6] 0-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function()
                return vm_dispatch(entry_state, {}, upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #7] 5-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c, d, e)
                return vm_dispatch(entry_state, {a, b, c, d, e},
                                   upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #8] 7-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c, d, e, f, g)
                return vm_dispatch(entry_state, {a, b, c, d, e, f, g},
                                   upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #9] Single reference count decrement
        function(slot)
            refcount_table[slot] = refcount_table[slot] - 1
            if 0 == refcount_table[slot] then
                refcount_table[slot], upvalue_store[slot] = nil, nil
            end
        end,

        -- [Helper #10] 10-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c, d, e, f, g, h, i, j)
                return vm_dispatch(entry_state,
                    {a, b, c, d, e, f, g, h, i, j}, upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #11] 3-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b, c)
                return vm_dispatch(entry_state, {a, b, c},
                                   upval_list, proxy)
            end
            return closure
        end,

        -- ================================================================
        -- [Helper #12] THE VM DISPATCHER
        -- This is the core of the Luraph virtual machine.
        -- It executes 546 dispatch states organized as a binary search tree.
        -- Each state performs one VM operation (load, call, compare, etc.)
        -- and sets the state variable to transition to the next operation.
        --
        -- Parameters:
        --   state     = initial dispatch state number (entry: 4,682,351)
        --   args      = argument table for this invocation
        --   upvals    = upvalue references from enclosing scope
        --   proxy     = GC-tracked proxy for automatic cleanup
        --
        -- The 76 local variables serve as the VM's register file.
        -- ================================================================
        function(state, args, upvals, proxy)
            local r01, r02, r03, r04, r05, r06, r07, r08, r09, r10,
                  r11, r12, r13, r14, r15, r16, r17, r18, r19, r20,
                  r21, r22, r23, r24, r25, r26, r27, r28, r29, r30,
                  r31, r32, r33, r34, r35, r36, r37, r38, r39, r40,
                  r41, r42, r43, r44, r45, r46, r47, r48, r49, r50,
                  r51, r52, r53, r54, r55, r56, r57, r58, r59, r60,
                  r61, r62, r63, r64, r65, r66, r67, r68, r69, r70,
                  r71, r72, r73, r74, r75, r76

            -- =============================================================
            -- MAIN DISPATCH LOOP
            -- Binary search tree: 545 comparison nodes, 546 leaf handlers
            -- State values range from 107,913 to 16,709,349
            -- Each handler sets `state` to the next state (unconditional),
            -- or `state = condition and stateA or stateB` (conditional).
            -- Dynamic transitions use `state = env[lookup(key)]` where the
            -- string table entry contains binary-encoded state numbers.
            -- =============================================================
            while state do
                if state < 8385482 then
                    if state < 4367185 then
                        if state < 2198657 then
                            -- ... 546 handler blocks ...
                            -- Each handler performs one of:
                            --
                            -- GETGLOBAL:   reg = env["string"]
                            -- GETTABLE:    reg = table["method"]
                            -- SETTABLE:    table["key"] = value
                            -- LOADCONST:   reg = "literal string"
                            -- CALL:        reg = func(args...)
                            -- CONCAT:      reg = a .. b
                            -- ARITH:       reg = a + b  (or -, *, /, %, ^)
                            -- COMPARE:     state = (a == b) and S1 or S2
                            -- LENGTH:      reg = #table
                            -- NOT:         reg = not value
                            -- NEWTABLE:    reg = {}
                            -- NEWCLOSURE:  reg = create_Narg_wrapper(state, upvals)
                            -- FORLOOP:     numeric for loop control
                            -- RETURN:      state = #proxy; return unpack_fn(varargs)
                            -- LOADNIL:     reg = nil
                            --
                            -- ANTI-TAMPER (state near 15,104,397):
                            --   reg = "error"
                            --   reg = "Tamper Detected!"
                            --   env["error"]("Tamper Detected!")
                        end
                    end
                end
                -- ... tree continues for ~13,000 lines ...
            end

            -- VM exit: return results
            state = #proxy
            return unpack_fn(varargs)
        end,

        -- [Helper #13] Initial stack pointer = 0
        0,

        -- [Helper #14] Upvalue storage table
        {},

        -- [Helper #15] 1-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a)
                return vm_dispatch(entry_state, {a}, upval_list, proxy)
            end
            return closure
        end,

        -- [Helper #16] Reference count table
        {},

        -- [Helper #17] Reference count setup + GC proxy creator
        -- Creates a GC-tracked proxy object that automatically decrements
        -- refcounts when garbage collected. Uses newproxy (LuaJIT/Lua 5.1)
        -- or falls back to setmetatable with __gc.
        function(upval_list)
            for i = 1, #upval_list, 1 do
                refcount_table[upval_list[i]] = 1 + refcount_table[upval_list[i]]
            end
            if newproxy_fn then
                local proxy = newproxy_fn(true)
                local mt = getmetatable_fn(proxy)
                mt[lookup(48673)],  -- __index
                mt[lookup(49054)],  -- __gc
                mt[lookup(48712)]   -- __len
                    = upval_list,
                      batch_decref,
                      function() return -3260189 end  -- sentinel value
                return proxy
            else
                return setmetatable_fn({}, {
                    [lookup(49054)] = batch_decref,  -- __gc
                    [lookup(48673)] = upval_list,     -- __index
                    [lookup(48712)] = function()      -- __len
                        return -3260189               -- sentinel value
                    end,
                })
            end
        end,

        -- [Helper #18] 2-argument closure wrapper
        function(entry_state, upval_list)
            local proxy = refcount_setup(upval_list)
            local closure = function(a, b)
                return vm_dispatch(entry_state, {a, b}, upval_list, proxy)
            end
            return closure
        end

    -- ====================================================================
    -- VM ENTRY POINT
    -- Creates a varargs closure at state 4,682,351 and immediately
    -- invokes it with the script's arguments.
    -- ====================================================================
    return (create_varargs_wrapper(4682351, {}))(unpack_fn(varargs))

    end)(
        getfenv and getfenv() or _ENV,   -- global environment
        unpack or table["unpack"],        -- unpack function
        newproxy,                          -- proxy creation (LuaJIT/5.1)
        setmetatable,                      -- metatable setter
        getmetatable,                      -- metatable getter
        select,                            -- select function
        {...}                              -- script arguments
    )
end)(...)  -- outer IIFE receives script-level varargs
```

### 4c. Closure Map (45 Functions in Original Program)

The VM creates 45 closures via the wrapper helpers, revealing the original program's function signatures:

| Entry State | Wrapper | Arity | Likely Purpose |
|---|---|---|---|
| **4,682,351** | `n` (varargs) | `...` | **Main entry point** |
| 14,783,007 | `G` (5-arg) | 5 | Main execution function (called via pcall) |
| 15,100,036 | `G` (5-arg) | 5 | Helper function (stored in upvalue) |
| 2,813,567 | `q` (0-arg) | 0 | Callback / thunk |
| 15,792,692 | `q` (0-arg) | 0 | Callback / thunk |
| 5,237,189 | `V` (1-arg) | 1 | Single-param handler |
| 5,664,548 | `V` (1-arg) | 1 | Single-param handler |
| 5,667,260 | `V` (1-arg) | 1 | Single-param handler |
| 5,871,381 | `V` (1-arg) | 1 | Single-param handler |
| 15,010,187 | `V` (1-arg) | 1 | Single-param handler |
| 16,197,224 | `V` (1-arg) | 1 | Single-param handler |
| 2,904,104 | `y` (2-arg) | 2 | Method-style function |
| 7,098,548 | `y` (2-arg) | 2 | Method-style function |
| 12,275,799 | `y` (2-arg) | 2 | Method-style function |
| 14,026,382 | `y` (2-arg) | 2 | Method-style function |
| *... 30 more ...* | | | |

**Arity distribution:** 0-arg: 2, 1-arg: 6, 2-arg: 4, 3-arg: 4, 4-arg: 7, 5-arg: 12, 6-arg: 8, 7-arg: 1, varargs: 1

---

## 5. Behavioral Analysis (any.run Sandbox)

### Network Activity

| # | Destination | Protocol | Purpose | Result |
|---|---|---|---|---|
| 1 | `ip-api.com` | HTTP GET | Victim geolocation fingerprint | **200 OK** -- returned location, ISP, VPN status |
| 2 | Ethereum RPC endpoint | HTTPS POST (JSON-RPC) | EtherHiding config retrieval via `getData()` | **401 Unauthorized** -- "API key disabled, tenant disabled" |
| 3 | `80.253.249.107:443` | TLS 1.3 / HTTP/2 | C2 communication via Yandex CDN | **No data exchanged** (4 attempts per run) |
| 4 | `login.live.com` | HTTPS (SOAP/WSS) | Windows Push Notification Service token | **Normal Windows background activity** (not malware) |

### ip-api.com Response (Sandbox Fingerprint)

```json
{
    "status": "success",
    "country": "Germany",
    "city": "Frankfurt am Main",
    "isp": "F.N.S. HOLDINGS LIMITED",
    "org": "VPN Consumer Frankfurt, Germany",
    "as": "AS206092 F.N.S. HOLDINGS LIMITED",
    "query": "91.217.249.42"
}
```

The sandbox was detected as a **VPN endpoint** in Frankfurt. Many SmartLoader variants check for VPN/datacenter IPs and alter behavior or refuse to execute in analysis environments.

### Ethereum JSON-RPC Call (EtherHiding)

```json
// Request
{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [{
        "to": "0x1823A9a0Ec8e0C25dD957D0841e3D41a4474bAdc",
        "data": "0x3bc5de30"
    }, "latest"],
    "id": 1
}

// Response (401 Unauthorized)
{
    "error": "message: API key disabled, reason: tenant disabled,
              json-rpc code: -32051, rest code: 403"
}
```

- **Contract:** `0x1823A9a0Ec8e0C25dD957D0841e3D41a4474bAdc`
- **Function selector:** `0x3bc5de30` = **`getData()`** ([4byte.directory](https://www.4byte.directory/))
- **Purpose:** Retrieve C2 configuration (URL, Host header, auth token) from blockchain
- **Chain:** Likely **Polygon** (not Ethereum mainnet) -- other SmartLoader samples connect to `polygon-rpc.com`
- **Status:** RPC provider revoked the attacker's API key

---

## 6. C2 Infrastructure

### Primary C2: 80.253.249.107 (Yandex Cloud CDN)

| Property | Value |
|---|---|
| **IP** | `80.253.249.107` |
| **Registered Owner** | QWINS LTD (AS213702) |
| **Actual Infrastructure** | **Yandex Cloud L7 Load Balancer** |
| **Location** | Frankfurt am Main, Germany |
| **Abuse Contact** | `abuse@qwins.co` (71-75 Shelton Street, London) |
| **TLS Certificate** | `*.yandex.tr` (GlobalSign ECC OV SSL CA 2018) |
| **Certificate Validity** | Feb 6, 2026 -- Aug 6, 2026 |
| **Certificate Subject** | `C=RU, ST=Moscow, L=Moscow, O=YANDEX LLC` |
| **Open Ports** | ~62,621 (virtually all ports -- characteristic of L7 balancer) |
| **VirusTotal** | Flagged as malicious. Community comment: "likely ViperSoftX" |

### Evidence of Live Yandex Infrastructure

The curl response headers confirm this is a **real Yandex balancer node**, not a spoofed certificate:

```
HTTP/2 406
x-yandex-req-id: 1771510330524375-16742565607671916846-balancer-l7leveler-kubr-yp-vla-127-BAL
set-cookie: _yasc=...; domain=.249.107; path=/; expires=Sun, 17 Feb 2036 14:12:10 GMT; secure
set-cookie: bh=...; Path=/; Domain=.249.107; SameSite=None; Secure
accept-ch: Sec-CH-UA-Platform-Version, Sec-CH-UA-Mobile, ...
```

**Breakdown of `x-yandex-req-id`:**
- `l7leveler` -- Yandex Layer 7 load balancer
- `kubr` -- Kubernetes routing layer
- `yp` -- Yandex Platform
- `vla` -- VLA datacenter (Vladimir, Russia)
- `BAL` -- Balancer designation

The HTTP 406 (Not Acceptable) response means the Yandex balancer is alive and processing requests, but **requires specific routing headers** (likely a `Host:` header with the attacker's Yandex-hosted domain name) that the malware would have obtained from the blockchain `getData()` call.

### Blockchain C2 Config: EtherHiding Architecture

```
┌─────────────┐    eth_call getData()     ┌──────────────────────┐
│  SmartLoader │ ───────────────────────>  │  Blockchain Contract │
│  (victim PC) │ <─────────────────────── │  (Polygon/BSC/ETH)   │
│              │    returns: C2 config     │  0x1823...bAdc       │
│              │    (host, path, token)    └──────────────────────┘
│              │
│              │    HTTPS + Host: <config> ┌──────────────────────┐
│              │ ───────────────────────>  │  Yandex L7 Balancer  │
│              │ <─────────────────────── │  80.253.249.107       │
│              │    C2 commands/payload    │  (*.yandex.tr cert)  │
└─────────────┘                           │         │             │
                                          │    routes to          │
                                          │         ▼             │
                                          │  ┌──────────────┐    │
                                          │  │ Attacker's    │    │
                                          │  │ Backend       │    │
                                          │  └──────────────┘    │
                                          └──────────────────────┘
```

**Why this architecture is effective:**
1. **Censorship resistance** -- Blockchain data cannot be taken down by authorities
2. **Dynamic reconfiguration** -- Attacker updates C2 details with a single blockchain transaction
3. **CDN legitimacy** -- Traffic appears as connections to Yandex (a major Russian CDN)
4. **Valid TLS** -- GlobalSign-issued certificate passes all validation checks
5. **Defense in depth** -- Killing the RPC key breaks the chain without exposing the backend

### Packet Capture Analysis (Local PCAP)

A packet capture from the victim's network (`out.pcapng`) contains **9 packets**, all outbound TCP SYN attempts from the infected host to `80.253.249.107`. No responses were received.

#### Connection Summary

| Run | Src Port | Dst Port | Packets | Time Span | Result |
|---|---|---|---|---|---|
| 1st execution | 50030 | **80** (HTTP) | 4 (SYN + 3 retrans) | 0.000s -- 1.547s | **No response** (SYN_SENT) |
| 2nd execution | 50042 | **80** (HTTP) | 5 (SYN + 4 retrans) | 50.525s -- 52.603s | **No response** (SYN_SENT) |

#### Raw Packet Detail (Stream 0, Initial SYN)

```
0000   d4 da 6d 9d 66 3e b8 19 75 7d 25 48 08 00 45 00   ..m.f>..u}%H..E.
0010   00 34 c5 c8 40 00 80 06 c5 e1 c0 a8 64 08 50 fd   .4..@.......d.P.
0020   f9 6b c3 6e 00 50 cd 3c e1 38 00 00 00 00 80 02   .k.n.P.<.8......
0030   ff ff 8d c2 00 00 02 04 05 b4 01 03 03 08 01 01   ................
0040   04 02                                             ..
```

#### Key Observations

1. **Port 80, not 443.** The malware attempts plain HTTP to the C2 IP, not HTTPS/443. This contrasts with the any.run sandbox data (which showed attempts on port 443) and the curl test (which confirmed a live Yandex L7 balancer on 443). This suggests the malware tries **multiple ports** or the blockchain config would have specified the correct port -- without it, the malware falls back to a hardcoded default (port 80) that doesn't work.

2. **Complete silence from the server.** No SYN-ACK, no RST. The server doesn't respond on port 80 at all. The Yandex L7 balancer is only active on port 443. Port 80 either has no listener or is firewall-dropped.

3. **Aggressive retransmission timing.** Retransmissions at ~0.5s intervals (standard TCP starts at 1s and doubles). This is the Windows TCP/IP stack default for SYN retransmissions, not a custom implementation -- the malware is using standard socket calls, not raw sockets.

4. **~50-second gap between attempts.** Stream 0 fails after ~1.5s (4 SYNs), then stream 1 starts at t=50.5s. This gap is the analyst running the malware a second time, not an internal retry mechanism. Each execution produces one connection attempt with 3-4 SYN retransmissions before giving up.

5. **Sequential IP identification numbers.** IP IDs increment by exactly 1 across all 9 packets (0xc5c8 through 0xc5d0), meaning virtually no other traffic was leaving this machine. Consistent with a clean VM or sandbox environment.

6. **Windows fingerprint confirmed.** TTL=128 (Windows default), Window=65535, WS=256 (multiply by 256), MSS=1460 (standard Ethernet). The TCP options order (MSS, NOP, WScale, NOP, NOP, SACK) matches Windows 10/11.

#### Host IOCs from PCAP

| IOC | Type | Value |
|---|---|---|
| Victim MAC | Ethernet | `b8:19:75:7d:25:48` |
| Gateway MAC | Ethernet | `d4:da:6d:9d:66:3e` |
| Victim LAN IP | IPv4 | `192.168.100.8` |
| Victim TCP raw seq (stream 0) | TCP | `3443319096` (0xCD3CE138) |
| Victim TCP raw seq (stream 1) | TCP | `3886003079` (0xE7B3CB87) |

---

## 7. Kill Chain Reconstruction

```
 PHASE 1: DELIVERY
 ─────────────────
 Victim downloads "upscalemp3_v2-v3.7.zip" (lure: fake audio tool)
 Distribution: SEO-poisoned GitHub repos, torrent sites, or fake tool sites
     │
     ▼
 PHASE 2: EXECUTION
 ──────────────────
 Launcher.cmd → start luajit.exe clib.txt
 LuaJIT interprets the obfuscated Lua script
     │
     ▼
 PHASE 3: LURAPH VM INITIALIZATION
 ─────────────────────────────────
 String table decoded (custom base64)
 Table shuffle applied
 18 helper functions initialized
 VM dispatcher enters state 4,682,351
 Anti-tamper checks validate line numbers via pcall
     │
     ▼
 PHASE 4: RECONNAISSANCE
 ───────────────────────
 HTTP GET → ip-api.com
 Returns: country, city, ISP, VPN status
 Purpose: Victim fingerprinting + sandbox detection
     │
     ▼
 PHASE 5: C2 CONFIG RETRIEVAL (EtherHiding)
 ──────────────────────────────────────────
 JSON-RPC → Blockchain contract 0x1823...bAdc
 Calls getData() (selector 0x3bc5de30)
 Expected return: C2 routing config (Host header, path, auth token)
 STATUS: ██ DEAD -- RPC API key revoked by provider
     │
     ▼
 PHASE 6: C2 COMMUNICATION
 ─────────────────────────
 TLS 1.3 → 80.253.249.107:443 (Yandex Cloud L7 Balancer)
 Certificate: *.yandex.tr (GlobalSign)
 Expected: Send config-derived Host header → routed to attacker backend
 STATUS: ██ BROKEN -- Missing config from Phase 5 → HTTP 406
     │
     ▼
 PHASE 7: PAYLOAD DELIVERY (not observed)
 ────────────────────────────────────────
 Expected: Download secondary payload:
   - Lumma Stealer
   - Redline Stealer
   - Rhadamanthys Stealer
 Delivered via file I/O (write + close patterns in VM)
     │
     ▼
 PHASE 8: DATA THEFT (not observed)
 ──────────────────────────────────
 Expected: Harvest browser credentials, crypto wallets, screenshots
 Exfiltrate via encrypted HTTP to C2
```

---

## 8. String Table Analysis

### API Surface (What the Malware Can Do)

#### Standard Library Access

| Library | Strings in Table | Usage Count in VM | Capabilities |
|---|---|---|---|
| `string` | `byte`, `char`, `find`, `gmatch`, `gsub`, `len`, `lower`, `match`, `sub`, `upper` | 25x `string`, 16x `gsub`, 9x `find`, 9x `sub`, 7x `lower` | Heavy string manipulation (decryption, assembly) |
| `table` | `concat`, `remove`, `unpack` | 12x `table` | Data structure operations |
| `math` | `floor`, `random` | 13x `math` | Arithmetic, randomization |
| `io` | `read`, `write`, `seek`, `close` | 6x `io`, 6x `write`, 6x `close`, 3x `seek`, 1x `read` | **File I/O operations** |
| `os` | `remove` | 1x `os` | OS-level operations |
| `debug` | *(accessed directly)* | 1x `debug` | Introspection / anti-analysis |

#### Dangerous Operations

| String | Z Key | VM Occurrences | Threat |
|---|---|---|---|
| `dofile` | 48462 | 1x | **Execute external Lua file** -- `pcall(dofile, path)` |
| `load` | 48970 | 1x | **Dynamic code execution** -- `load(string)` compiles and runs arbitrary code |
| `require` | 48864 | 2x | **Module loading** -- can load native C modules / DLLs |
| `currentDllPath` | 48669 | 2x | **DLL path access** -- references companion native code |
| `error` | 48964 | 2x | Error throwing (tamper detection + controlled errors) |
| `pcall` | 48617 | 7x | Protected calls (error suppression, anti-tamper) |

#### Anti-Analysis Strings

| String | Z Key | Purpose |
|---|---|---|
| `Tamper Detected!` | 48578 | Anti-tamper error message |
| `:(%d*):` | 49439 | Lua pattern for extracting line numbers from error messages |
| `debug` | 49482 | Access to debug library for introspection |

#### Metatable / Proxy Strings

| String | Z Key | Purpose |
|---|---|---|
| `__index` | 48673 | Index metamethod (upvalue access via proxy) |
| `__gc` | 49054 | Garbage collection hook (automatic cleanup) |
| `__len` | 48712 | Length metamethod (sentinel value check) |
| `__metatable` | 49124 | Metatable protection (prevents inspection) |
| `setmetatable` | 49043 | Metatable manipulation |

#### Obfuscation Key Strings

~60 random alphanumeric identifiers (e.g., `Xj5NkpMjKp1u3u`, `ChKg6ubWvFBx`, `9bRJ6DD7DPYa`) serve as randomized table keys in the virtualized program's data structures.

### Notable Absences

The string table contains **no direct network strings**: no `http`, `socket`, `url`, `connect`, `send`, `recv`, `tcp`, `udp`, or domain names. Network operations are likely performed through:
- Dynamically constructed strings (via the heavy `gsub`/`concat` usage)
- Native code loaded via `require` or `currentDllPath`
- External Lua files loaded via `dofile`

---

## 9. Indicators of Compromise (IOCs)

### Network IOCs

| IOC | Type | Context |
|---|---|---|
| `80.253.249.107` | IP (C2) | Yandex Cloud L7 Balancer. QWINS LTD, AS213702, Frankfurt. Valid `*.yandex.tr` cert. |
| `0x1823A9a0Ec8e0C25dD957D0841e3D41a4474bAdc` | Blockchain Address | Smart contract for EtherHiding C2 config. `getData()` selector `0x3bc5de30`. Likely Polygon chain. |
| `ip-api.com` | Domain (Recon) | Victim geolocation / VPN / sandbox fingerprinting |
| `*.yandex.tr` | TLS Certificate CN | Legitimate Yandex cert served by C2 infrastructure |

### File IOCs

| IOC | Type | Value |
|---|---|---|
| `Launcher.cmd` | Filename | Batch launcher (defanged to `.cmdx` in archive) |
| `luajit.exe` | Filename | LuaJIT executable (defanged to `.exex` in archive) |
| `clib.txt` | Filename | Luraph-obfuscated Lua payload (355,768 bytes, 1 line) |
| `lua51.dll` | Filename | LuaJIT runtime library |
| `start luajit.exe clib.txt` | Command | Launcher content |
| `Tamper Detected!` | String | Anti-tamper error message in Luraph VM |
| `currentDllPath` | String | DLL reference in string table |

### Behavioral IOCs

| Behavior | Detail |
|---|---|
| LuaJIT execution of `.txt` file | `luajit.exe clib.txt` -- text file is actually Lua source |
| Ethereum JSON-RPC `eth_call` | `getData()` on smart contract for config retrieval |
| HTTP GET to `ip-api.com` | Geolocation fingerprinting |
| TLS to IP with Yandex cert | Connection to raw IP serving `*.yandex.tr` certificate |
| TCP SYN to C2 port 80 (no response) | Fallback/default port when blockchain config unavailable (PCAP evidence) |
| Single C2 connection attempt per execution | One SYN + 3-4 retransmissions, then gives up (PCAP shows two runs by analyst) |
| ~62K open ports on C2 IP | Yandex L7 balancer characteristic |
| Lua payload disguised as `.txt` | `clib.txt` -- Lua source code disguised as a text file |

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Initial Access** | Phishing / SEO Poisoning | T1566 / T1608.006 | Fake "upscalemp3" audio tool distributed via poisoned search results |
| **Execution** | Command and Scripting Interpreter: Lua | T1059 | LuaJIT executes obfuscated Lua script |
| **Defense Evasion** | Obfuscated Files or Information: Software Packing | T1027.002 | Luraph bytecode virtualizer with 546-state VM |
| **Defense Evasion** | Masquerading: Match Legitimate Name | T1036.005 | Payload named `clib.txt` appears to be text file |
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497 | ip-api.com VPN/datacenter detection |
| **Defense Evasion** | Debugger Evasion | T1622 | Anti-tamper via pcall line-number validation |
| **Discovery** | System Location Discovery | T1614 | ip-api.com geolocation query |
| **Command and Control** | Web Service: Dead Drop Resolver | T1102.001 | Blockchain smart contract `getData()` for C2 config |
| **Command and Control** | Encrypted Channel: Asymmetric Cryptography | T1573.002 | TLS 1.3 to Yandex CDN with valid certificate |
| **Command and Control** | Domain Fronting | T1090.004 | C2 behind Yandex Cloud L7 balancer with `*.yandex.tr` cert |
| **Command and Control** | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/2 over TLS for C2 communication |
| **Execution** | Native API | T1106 | `currentDllPath`, `require` for native code loading |
| **Execution** | Shared Modules | T1129 | DLL loading via LuaJIT FFI / require |

---

## 11. References

### Malware Family Research

- [SmartLoader LuaJIT Analysis -- Intellibron](https://blog.intellibron.io/lua-jit-smartloader-analyzing-the-github-campaign-delivering-stealer/)
- [JIT Happens: Exposing LuaJIT Malware -- SecurityBlue Team](https://www.securityblue.team/blog/posts/jit-happens-exposing-luajit-malware-in-the-wild)
- [SmartLoader Distribution via GitHub -- ASEC/AhnLab](https://asec.ahnlab.com/en/89551/)
- [SmartLoader Large-scale Infiltration -- Gatewatcher](https://www.gatewatcher.com/en/lab/smartloader-large-scale-infiltration-via-github-uncovered-by-gatewatcher-purple-team/)
- [ViperSoftX Updates -- Trend Micro](https://www.trendmicro.com/en_us/research/23/d/vipersoftx-updates-encryption-steals-data.html)
- [ViperSoftX Tracking -- CUJO AI](https://cujo.com/blog/vipersoftx-tracking-and-countering-a-persistent-threat/)
- [ViperSoftX DGA Evolution -- Chris Partridge](https://chris.partridge.tech/2022/evolution-of-vipersoftx-dga/)

### Obfuscator Research

- [Luraph Official Site](https://lura.ph/)
- [Lua Devirtualization Part 3: Devirtualizing Luraph -- Ferib](https://ferib.dev/blog/lua-devirtualization-part-3-devirtualizing-luraph/)
- [Luraph v14.2 Anti-Format Bypass -- TechHog8984](https://gist.github.com/TechHog8984/2e41a77e1d62b5b9d91a5e84274cdf45)
- [LuraphDeobfuscator -- TheGreatSageEqualToHeaven / PhoenixZeng](https://github.com/PhoenixZeng/LuraphDeobfuscator)
- [Lua Virtualization Part 2: Obfuscation Techniques -- birk.blog](https://birk.blog/posts/lua_virtualization_part_2/)

### EtherHiding / Blockchain C2

- [DPRK Adopts EtherHiding -- Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding)
- [UNC5142 Leverages EtherHiding -- Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware)
- [Smargaft Harnesses EtherHiding -- QiAnXin XLab](https://blog.xlab.qianxin.com/smargaft_abusing_binance-smart-contracts_en/)
- [Ethereum Smart Contracts in npm Malware -- ReversingLabs](https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code)
- [EtherHiding Explained -- Picus Security](https://www.picussecurity.com/resource/blog/etherhiding-how-web3-infrastructure-enables-stealthy-malware-distribution)

### Tools and Databases

- [4byte.directory -- Ethereum Function Selector Database](https://www.4byte.directory/)
- [Etherscan -- Ethereum Blockchain Explorer](https://etherscan.io/)
- [AbuseIPDB -- IP Reputation Database](https://www.abuseipdb.com/)
- [IPinfo -- IP Geolocation and ASN Data](https://ipinfo.io/)

---

## 12. The Story Behind the Code

### 12a. Who Made This

This wasn't built by one person. It's an assembly line product.

The **Luraph VM** was written by a skilled Lua developer -- likely a young programmer embedded in the Roblox modding community. Luraph has been a commercial service since 2017, originally built to protect Roblox game scripts from theft by other developers. The author sells obfuscation as a legitimate service at [lura.ph](https://lura.ph/). They almost certainly did not build it for malware. But the tool doesn't care who buys a license, and neither does the author's payment processor. The same technology that stops a 14-year-old from stealing your Roblox game code now protects a credential stealer from reverse engineers.

The **SmartLoader operator** -- the person who actually weaponized this sample -- is a different actor entirely. They are likely:

- **Eastern European or CIS-region based**, given the Yandex Cloud infrastructure choice, Russian-issued TLS certificates, and operational familiarity with Yandex's CDN routing. The QWINS LTD shell company registered at a London virtual office address (71-75 Shelton Street -- one of the most overused nominee addresses in the UK) is a standard bulletproof hosting front.
- **Technically competent but not elite**. They didn't write the VM, they bought it. They didn't discover EtherHiding, they copied the technique from public threat intelligence reports about DPRK campaigns. They chose Yandex Cloud because it's familiar to them, not because it's the best CDN for domain fronting. The real engineering is in the plumbing -- stitching together off-the-shelf components (Luraph, LuaJIT, EtherHiding, Yandex CDN) into a working delivery chain.
- **Part of the MaaS (Malware-as-a-Service) ecosystem**. SmartLoader is a **loader**, not the final payload. The operator's business model is access brokering: compromise machines cheaply and at scale, then sell that access to stealer operators (Lumma, Redline, Rhadamanthys) who pay per install. The loader operator never touches the stolen credentials themselves -- they're a middleman.
- **Running multiple campaigns simultaneously**. The "upscalemp3" lure is one of dozens. Other documented SmartLoader lures include fake AI tools, game cheats, cracked software, and developer utilities. Each campaign targets a different audience on a different platform with a different fake name, but they all phone home to the same infrastructure.
- **Operating with a budget**. They pay for Luraph licenses, blockchain RPC API keys, Yandex Cloud hosting, and shell company registration. This isn't a hobbyist. The per-install revenue from stealer operators funds the infrastructure, and the margins are good enough to keep the operation running.

Their profile: **a mid-tier cybercrime operator in the CIS region, likely in their 20s or 30s, running SmartLoader as one component of a broader access-brokering business.** Not a nation-state. Not an APT. Just someone who figured out that the path from "fake software download" to "stolen crypto wallet" can be automated, outsourced, and scaled.

### 12b. What Happens to the Victim

The victim's story starts with a search engine.

They want to convert an MP3 file, upscale audio quality, or process some media. They search for a tool. Somewhere on the first page of results -- or in a GitHub repository that looks legitimate, complete with stars, forks, and a professional README -- they find "upscalemp3 v3.7". It might have a nice landing page. It might have fake user reviews. It might be a forked copy of a real audio tool with the malware injected into the release assets.

They download the ZIP. Inside are four files. Nothing looks dangerous -- an exe, a dll, a text file, and a cmd script. They double-click `Launcher.cmd`. A command prompt flashes briefly. Nothing visible happens. The "tool" doesn't appear to launch.

Most victims close the window, maybe try again, maybe search for troubleshooting help, and eventually forget about it.

**But in the background, in the seconds after that double-click:**

1. LuaJIT loaded and executed the obfuscated script
2. The Luraph VM initialized its 546-state interpreter
3. The malware fingerprinted their location via ip-api.com
4. A blockchain smart contract was queried for C2 configuration
5. If the C2 chain was operational, a secondary payload was downloaded and executed

For victims hit during the campaign's active window (before the RPC key was revoked), the secondary payload -- typically Lumma Stealer or Rhadamanthys -- would have:

- **Harvested every saved password** from Chrome, Firefox, Edge, and other browsers
- **Extracted cryptocurrency wallet files** and seed phrases
- **Stolen session cookies** for Discord, Telegram, and other platforms (allowing account takeover without needing the password)
- **Captured screenshots** of the victim's desktop
- **Copied browser autofill data** including names, addresses, and stored credit card numbers
- **Exfiltrated the data** to a stealer C2 server within seconds

The victim has no idea any of this happened. There is no visible infection. There is no ransomware note. There is no performance degradation. The first sign of compromise is typically:

- A cryptocurrency wallet drained days or weeks later
- A Discord account posting scam links
- An email account sending phishing messages
- A bank flagging unauthorized transactions
- A password manager breach notification from a service they use

By then, the stolen credentials have been bundled into "logs" and sold on underground markets. The buyer may be a different criminal entirely -- someone who specializes in cashing out stolen crypto, or taking over social media accounts, or committing identity fraud. The original SmartLoader operator is long gone, having already been paid their per-install fee.

### 12c. What Should Be Done

#### What the Community Should Do

**Researchers and analysts:**
- **Publish IOCs immediately** when you find them. The blockchain address, C2 IP, and file hashes in this report should be in every threat feed. Speed kills campaigns -- the faster these indicators propagate to endpoint protection, the shorter the window of active exploitation.
- **Monitor the smart contract**. Even though the RPC key is dead, the contract `0x1823...bAdc` still exists on-chain. If the operator deploys a new contract or updates the existing one with a fresh RPC endpoint, the campaign can restart overnight. Blockchain monitoring is cheap and can provide early warning.
- **Track Luraph-protected samples**. The Luraph VM has identifiable signatures (the `Tamper Detected!` string, the binary search dispatch, the `newproxy`/`__gc` pattern). A YARA rule matching these patterns would catch new SmartLoader variants regardless of their lure theme.

**End users:**
- **Never execute software from unverified GitHub repositories**, especially ones that appeared recently, have inflated star counts, or contain release assets that don't match the repository's source code.
- **Check file extensions carefully**. A `.txt` file that is actually executable code is a red flag. If a "tool" ships as a bare LuaJIT binary + a `.cmd` launcher instead of a proper installer, it's not legitimate software.
- **Assume compromise if you ran it**. If you executed this sample (or anything matching the SmartLoader package structure), immediately change all passwords saved in your browser, revoke all active sessions, enable 2FA everywhere, and move cryptocurrency to new wallets with fresh seed phrases. The old credentials are burned.

#### What GitHub Should Do

GitHub is the **primary distribution vector** for SmartLoader campaigns. Multiple independent reports (Intellibron, ASEC/AhnLab, Gatewatcher) document large-scale abuse of GitHub repositories to host and distribute these exact payloads. GitHub, backed by Microsoft's resources, is uniquely positioned to break this distribution chain:

1. **Scan release assets, not just source code**. GitHub currently focuses security scanning on repository source code (Dependabot, CodeQL, secret scanning). SmartLoader payloads live in **release assets** -- ZIP files attached to GitHub Releases that bypass all source-level scanning. GitHub should decompress and scan release assets for known malware signatures before they're served to users. Microsoft Defender's engine could do this today.

2. **Flag the LuaJIT+obfuscated-script package pattern**. The SmartLoader signature is distinctive: a LuaJIT binary + `lua51.dll` + a large single-line text file + a batch launcher. This 4-file combination in a release asset should trigger automated review. It has virtually no legitimate use case in GitHub Releases.

3. **Enforce release asset provenance**. GitHub Actions can build and sign release artifacts with Sigstore/cosign. Repositories that upload release assets manually (not through CI/CD) should display a prominent warning to downloaders: "This release was uploaded manually and has not been built from the repository's source code." This single change would undermine the core SmartLoader social engineering: the victim trusts the download because it's "from GitHub."

4. **Rate-limit repository creation patterns**. SmartLoader operators create dozens of repositories across throwaway accounts, all with similar structures (professional README, inflated stars, release assets that don't match the code). GitHub's abuse detection should correlate these patterns: new account + immediate release upload + executable in assets + no CI/CD history = high-risk.

5. **Publish transparency reports on malware distribution**. GitHub should report how many repositories distributing malware were identified and removed per quarter, the average time from upload to takedown, and the estimated number of downloads before removal. Transparency creates accountability and helps the community assess whether GitHub's defenses are improving.

#### What Microsoft Should Do (Beyond GitHub)

Microsoft owns both the distribution vector (GitHub) and the dominant endpoint (Windows). This gives them end-to-end visibility:

- **Windows Defender should flag LuaJIT-based execution chains**. The pattern of `cmd.exe` launching `luajit.exe` with a `.txt` argument is anomalous and should trigger at minimum a SmartScreen warning. This behavioral detection doesn't require signature updates -- it's a heuristic that catches the entire SmartLoader family.
- **SmartScreen should warn on LuaJIT-based packages**. A folder containing `luajit.exe` + `lua51.dll` + a `.txt` or `.dat` payload + a batch launcher is a known malware pattern. SmartScreen should flag this combination when downloaded from the internet, similar to how it already warns on other known-bad patterns.
- **Coordinate with blockchain RPC providers**. The RPC key revocation that killed this campaign's first stage was likely triggered by an abuse report. Microsoft's threat intelligence team (MSTIC) should establish standing relationships with major RPC providers (Infura, Alchemy, QuickNode, Ankr) to fast-track abuse reports for blockchain addresses used in EtherHiding campaigns. A 24-hour response time on RPC key revocation can reduce a campaign's active window from weeks to days.
