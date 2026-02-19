I noticed some freaky syntax errors in vscode you can see the style of them in @01-obfuscated/example.lua the exact errors are:

```log
<eof> expected after `return`.
Lua should use `--` for annotations.
Unexpected symbol `)`.
Unexpected <exp> .
Missed symbol `)`.
Unexpected symbol `,`.
Unexpected <exp> .
Unexpected symbol `,`.
Unexpected <exp> .
Unexpected symbol `)`.
Unexpected <exp> .
Undefined global `n`.
Undefined global `E`.
Undefined global `w`.
Undefined global `_ENV`.
Undefined global `Z`.
Undefined global `e`.
```

I asked another agent about it and we had this discussion: @chat01.md

What do you think, would it be possible to easily undo this kind of anti-debugging anti-analysis trickery or is it not worth the time and effort, especially if it makes the code more brittle.

