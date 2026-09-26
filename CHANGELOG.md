# Changelog

## Syntax Highlighting Fix

### Problems found

1. **Extension-only detection**: Language detection relied solely on file extension
   (`path.extension()`). Files without extensions like `Makefile`, `Dockerfile`,
   `CMakeLists.txt`, and `Justfile` were never highlighted.

2. **Silent regex failures**: The call `let _ = textarea.set_search_pattern(pattern)`
   discarded the `Result`, so if a regex pattern failed to compile, highlighting
   would silently not work with no indication of what went wrong.

3. **Style visibility**: `Color::Yellow` can be invisible or hard to read on
   terminals with light backgrounds or certain color themes.

### Fixes applied

1. **Filename + extension detection**: `highlight.rs` now checks both the file
   extension AND the full filename. This enables detection of:
   - `Makefile` / `GNUmakefile` / `*.mk` → Makefile keywords
   - `Dockerfile` → Dockerfile directives (FROM, RUN, COPY, etc.)
   - `CMakeLists.txt` / `*.cmake` → CMake keywords
   - `Justfile` → Just/Make keywords
   - `Rakefile` / `Gemfile` → Ruby keywords

2. **Error handling on regex**: Changed from `let _ = textarea.set_search_pattern()`
   to a `match` that explicitly handles `Ok` and `Err`. If the pattern fails to
   compile, highlighting is simply disabled for that file (no crash, no silent bug).

3. **Brighter color**: Changed from `Color::Yellow` to `Color::LightYellow` for
   better visibility across terminal themes.

4. **Expanded language support**: Added keyword patterns for:
   - Makefile, Dockerfile, CMake
   - Swift, Kotlin
   - C preprocessor directives (`#include`, `#define`, etc.)
   - TOML (true/false)
   - More shell builtins (trap, eval, exec, shift)

### Architecture of the fix

The `highlight.rs` module now has two lookup paths:

```
keyword_pattern(filename, ext)
  ├── pattern_from_ext(ext)       — tries extension first (fast path)
  └── pattern_from_filename(name) — falls back to full filename match
```

Same for `detect_language(filename, ext)`.

The editor extracts both values from the path:
```rust
let filename = path.file_name();  // "Makefile", "foo.rs", etc.
let ext = path.extension();       // "rs", "py", "" for Makefile
```

Both are passed to the highlight module, which tries extension first
(covers 95% of cases) then falls back to filename matching.
