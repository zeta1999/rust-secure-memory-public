//! Trivial syntax highlighting via keyword regex patterns.
//!
//! Uses `tui-textarea`'s search-pattern feature to highlight language
//! keywords in a single colour. Detects language from file extension
//! or filename (Makefile, Dockerfile, etc.).

/// Detect language name from file path for status bar display.
/// Checks extension first, then falls back to filename matching.
pub fn detect_language(filename: &str, ext: &str) -> Option<&'static str> {
    // Try extension first
    if let Some(lang) = lang_from_ext(ext) {
        return Some(lang);
    }
    // Fall back to filename
    lang_from_filename(filename)
}

/// Return a keyword regex for the given file path.
/// Checks extension first, then falls back to filename matching.
pub fn keyword_pattern(filename: &str, ext: &str) -> Option<&'static str> {
    if let Some(pat) = pattern_from_ext(ext) {
        return Some(pat);
    }
    pattern_from_filename(filename)
}

fn lang_from_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "rs" => Some("Rust"),
        "py" | "pyw" => Some("Python"),
        "js" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "mts" => Some("TypeScript"),
        "jsx" | "tsx" => Some("React"),
        "c" | "h" => Some("C"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some("C++"),
        "go" => Some("Go"),
        "sh" | "bash" | "zsh" => Some("Shell"),
        "rb" => Some("Ruby"),
        "java" => Some("Java"),
        "toml" => Some("TOML"),
        "yaml" | "yml" => Some("YAML"),
        "json" => Some("JSON"),
        "md" | "markdown" => Some("Markdown"),
        "sql" => Some("SQL"),
        "html" | "htm" => Some("HTML"),
        "css" => Some("CSS"),
        "lua" => Some("Lua"),
        "zig" => Some("Zig"),
        "pl" | "pm" => Some("Perl"),
        "r" | "R" => Some("R"),
        "swift" => Some("Swift"),
        "kt" | "kts" => Some("Kotlin"),
        "ex" | "exs" => Some("Elixir"),
        "erl" | "hrl" => Some("Erlang"),
        "hs" => Some("Haskell"),
        "ml" | "mli" => Some("OCaml"),
        "cmake" => Some("CMake"),
        _ => None,
    }
}

fn lang_from_filename(filename: &str) -> Option<&'static str> {
    let lower = filename.to_lowercase();
    match lower.as_str() {
        "makefile" | "gnumakefile" => Some("Makefile"),
        "dockerfile" => Some("Dockerfile"),
        "cmakelists.txt" => Some("CMake"),
        "rakefile" | "gemfile" => Some("Ruby"),
        "justfile" => Some("Just"),
        _ => {
            // Check for shebang-like patterns in the name
            if lower.ends_with(".mk") {
                Some("Makefile")
            } else {
                None
            }
        }
    }
}

fn pattern_from_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "rs" => Some(RUST),
        "py" | "pyw" => Some(PYTHON),
        "js" | "mjs" | "cjs" | "jsx" => Some(JAVASCRIPT),
        "ts" | "mts" | "tsx" => Some(TYPESCRIPT),
        "c" | "h" => Some(C_LANG),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(CPP),
        "go" => Some(GO),
        "sh" | "bash" | "zsh" => Some(SHELL),
        "rb" => Some(RUBY),
        "java" => Some(JAVA),
        "lua" => Some(LUA),
        "zig" => Some(ZIG),
        "sql" => Some(SQL),
        "toml" => Some(TOML),
        "cmake" => Some(CMAKE),
        "swift" => Some(SWIFT),
        "kt" | "kts" => Some(KOTLIN),
        _ => None,
    }
}

fn pattern_from_filename(filename: &str) -> Option<&'static str> {
    let lower = filename.to_lowercase();
    match lower.as_str() {
        "makefile" | "gnumakefile" => Some(MAKEFILE),
        "dockerfile" => Some(DOCKERFILE),
        "cmakelists.txt" => Some(CMAKE),
        "justfile" => Some(MAKEFILE), // close enough
        _ => {
            if lower.ends_with(".mk") {
                Some(MAKEFILE)
            } else {
                None
            }
        }
    }
}

// ── Keyword patterns ─────────────────────────────────────────
// Each is a regex matching whole words only (\b).

const RUST: &str = r"\b(fn|let|pub|use|struct|enum|impl|mod|mut|if|else|for|while|loop|match|return|const|static|type|trait|where|async|await|self|super|crate|true|false|Some|None|Ok|Err|Self|unsafe|ref|move|dyn|extern|macro|as|in)\b";

const PYTHON: &str = r"\b(def|class|if|elif|else|for|while|return|import|from|as|with|try|except|finally|raise|pass|break|continue|and|or|not|in|is|None|True|False|self|lambda|yield|async|await|global|nonlocal|print)\b";

const JAVASCRIPT: &str = r"\b(function|const|let|var|if|else|for|while|return|class|import|export|from|async|await|try|catch|finally|throw|new|this|typeof|instanceof|true|false|null|undefined|switch|case|default|break|continue|yield)\b";

const TYPESCRIPT: &str = r"\b(function|const|let|var|if|else|for|while|return|class|import|export|from|async|await|try|catch|finally|throw|new|this|typeof|instanceof|true|false|null|undefined|interface|type|enum|namespace|abstract|implements|extends|switch|case|default|break|continue)\b";

const C_LANG: &str = r"\b(int|char|float|double|void|if|else|for|while|do|return|struct|enum|typedef|const|static|extern|sizeof|switch|case|break|continue|unsigned|signed|long|short|NULL|register|volatile|union|goto|default|include|define|ifdef|ifndef|endif)\b";

const CPP: &str = r"\b(int|char|float|double|void|bool|if|else|for|while|do|return|struct|class|enum|typedef|const|static|extern|sizeof|switch|case|break|continue|namespace|using|template|typename|virtual|override|public|private|protected|new|delete|true|false|nullptr|auto|constexpr|noexcept|throw|try|catch|include|define)\b";

const GO: &str = r"\b(func|var|const|if|else|for|range|return|struct|interface|type|package|import|defer|go|chan|select|switch|case|break|continue|map|make|append|len|cap|true|false|nil|err|string|int|bool|byte|error|fmt)\b";

const SHELL: &str = r"\b(if|then|else|elif|fi|for|while|do|done|case|esac|function|return|exit|echo|export|local|source|set|unset|true|false|in|select|until|readonly|declare|typeset|shift|trap|eval|exec)\b";

const RUBY: &str = r"\b(def|class|module|if|elsif|else|unless|while|until|for|do|end|return|require|include|extend|attr_accessor|attr_reader|attr_writer|true|false|nil|self|super|yield|begin|rescue|ensure|raise|then|puts|print)\b";

const JAVA: &str = r"\b(public|private|protected|class|interface|enum|if|else|for|while|do|return|void|int|boolean|String|static|final|new|this|super|try|catch|finally|throw|throws|import|package|extends|implements|abstract|synchronized|volatile|true|false|null)\b";

const LUA: &str = r"\b(function|local|if|then|else|elseif|end|for|while|do|repeat|until|return|and|or|not|in|true|false|nil|require|print|table|string|math|io|pairs|ipairs)\b";

const ZIG: &str = r"\b(fn|const|var|if|else|for|while|return|struct|enum|union|switch|break|continue|pub|comptime|try|catch|unreachable|undefined|null|true|false|test|defer|errdefer|import|export|inline|extern)\b";

const SQL: &str = r"(?i)\b(SELECT|FROM|WHERE|INSERT|INTO|UPDATE|SET|DELETE|CREATE|DROP|ALTER|TABLE|INDEX|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AND|OR|NOT|IN|IS|NULL|AS|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|UNION|VALUES|PRIMARY|KEY|FOREIGN|REFERENCES|DISTINCT|COUNT|SUM|AVG|MAX|MIN|LIKE|BETWEEN|EXISTS|CASE|WHEN|THEN|ELSE|END|BEGIN|COMMIT|ROLLBACK)\b";

const TOML: &str = r"\b(true|false)\b";

const CMAKE: &str = r"\b(project|cmake_minimum_required|set|add_executable|add_library|target_link_libraries|find_package|include_directories|install|if|else|elseif|endif|option|message|foreach|endforeach|function|endfunction|macro|endmacro)\b";

const MAKEFILE: &str = r"\b(ifeq|ifneq|ifdef|ifndef|else|endif|define|endef|include|override|export|unexport|all|clean|install|uninstall|phony|wildcard|patsubst|shell|error|warning|info)\b";

const DOCKERFILE: &str = r"\b(FROM|RUN|CMD|ENTRYPOINT|COPY|ADD|ENV|ARG|EXPOSE|VOLUME|WORKDIR|USER|LABEL|HEALTHCHECK|SHELL|STOPSIGNAL|ONBUILD|AS)\b";

const SWIFT: &str = r"\b(func|var|let|if|else|for|while|return|class|struct|enum|protocol|import|switch|case|break|continue|guard|defer|throw|throws|try|catch|true|false|nil|self|super|public|private|internal|fileprivate|open|static|override|init|deinit|extension|where|as|is|in)\b";

const KOTLIN: &str = r"\b(fun|val|var|if|else|for|while|return|class|object|interface|enum|import|when|break|continue|throw|try|catch|finally|true|false|null|this|super|is|as|in|out|public|private|protected|internal|override|abstract|open|data|sealed|companion)\b";
