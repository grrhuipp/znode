const std = @import("std");

/// Lightweight regex engine for domain matching.
/// Supports: . * + ? [] [^] \d \w \s ^ $ (case-insensitive)
///
/// Uses recursive backtracking — suitable for short patterns on short strings
/// (domain names are typically < 256 chars, patterns < 64 chars).

/// Match a regex pattern against text (case-insensitive, unanchored by default).
/// Unanchored: pattern can match anywhere in the text unless ^ or $ are used.
pub fn match(pattern: []const u8, text: []const u8) bool {
    if (pattern.len == 0) return true;

    // If pattern starts with ^, anchor to start
    if (pattern[0] == '^') {
        return matchHere(pattern[1..], text);
    }

    // Try matching at each position
    for (0..text.len + 1) |i| {
        if (matchHere(pattern, text[i..])) return true;
    }
    return false;
}

/// Match pattern at exact position in text.
fn matchHere(pattern: []const u8, text: []const u8) bool {
    if (pattern.len == 0) return true;

    // $ at end of pattern: match end of text
    if (pattern.len == 1 and pattern[0] == '$') {
        return text.len == 0;
    }

    // Parse current atom and check for quantifier
    const atom_len = atomLength(pattern);
    if (atom_len == 0) return false;

    const after_atom = pattern[atom_len..];
    const has_quantifier = after_atom.len > 0 and
        (after_atom[0] == '*' or after_atom[0] == '+' or after_atom[0] == '?');

    if (has_quantifier) {
        const quantifier = after_atom[0];
        const rest = after_atom[1..];
        return matchQuantified(pattern[0..atom_len], quantifier, rest, text);
    }

    // No quantifier: match exactly one
    if (text.len == 0) return false;
    if (!matchAtom(pattern[0..atom_len], text[0])) return false;
    return matchHere(after_atom, text[1..]);
}

/// Match an atom with a quantifier (*, +, ?)
fn matchQuantified(atom: []const u8, quantifier: u8, rest: []const u8, text: []const u8) bool {
    switch (quantifier) {
        '?' => {
            // 0 or 1
            if (matchHere(rest, text)) return true;
            if (text.len > 0 and matchAtom(atom, text[0])) {
                return matchHere(rest, text[1..]);
            }
            return false;
        },
        '*' => {
            // 0 or more (greedy)
            // Count max matches
            var count: usize = 0;
            while (count < text.len and matchAtom(atom, text[count])) : (count += 1) {}
            // Try from longest match down (greedy)
            var i: usize = count + 1;
            while (i > 0) {
                i -= 1;
                if (matchHere(rest, text[i..])) return true;
            }
            return false;
        },
        '+' => {
            // 1 or more (greedy)
            var count: usize = 0;
            while (count < text.len and matchAtom(atom, text[count])) : (count += 1) {}
            if (count == 0) return false;
            var i: usize = count + 1;
            while (i > 1) {
                i -= 1;
                if (matchHere(rest, text[i..])) return true;
            }
            return false;
        },
        else => return false,
    }
}

/// Get the length (in bytes) of the current atom in the pattern.
fn atomLength(pattern: []const u8) usize {
    if (pattern.len == 0) return 0;
    return switch (pattern[0]) {
        '\\' => if (pattern.len >= 2) 2 else 1,
        '[' => bracketLength(pattern),
        '.', '^', '$' => 1,
        else => 1,
    };
}

/// Get the length of a bracket expression [...]
fn bracketLength(pattern: []const u8) usize {
    if (pattern.len < 2 or pattern[0] != '[') return 1;
    var i: usize = 1;
    // Handle [^ negation
    if (i < pattern.len and pattern[i] == '^') i += 1;
    // Handle ] as first char in class
    if (i < pattern.len and pattern[i] == ']') i += 1;
    while (i < pattern.len) {
        if (pattern[i] == ']') return i + 1;
        i += 1;
    }
    return pattern.len; // unterminated bracket
}

/// Check if a single character matches an atom.
fn matchAtom(atom: []const u8, ch: u8) bool {
    if (atom.len == 0) return false;
    return switch (atom[0]) {
        '.' => true, // any character
        '\\' => if (atom.len >= 2) matchEscape(atom[1], ch) else false,
        '[' => matchBracket(atom, ch),
        else => charEqI(atom[0], ch),
    };
}

/// Case-insensitive character comparison.
fn charEqI(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

/// Match an escape sequence (\d, \w, \s, or literal).
fn matchEscape(escape_char: u8, ch: u8) bool {
    return switch (escape_char) {
        'd' => std.ascii.isDigit(ch),
        'D' => !std.ascii.isDigit(ch),
        'w' => std.ascii.isAlphanumeric(ch) or ch == '_',
        'W' => !(std.ascii.isAlphanumeric(ch) or ch == '_'),
        's' => std.ascii.isWhitespace(ch),
        'S' => !std.ascii.isWhitespace(ch),
        else => ch == escape_char, // literal: \. \* \+ etc.
    };
}

/// Match a bracket expression [abc], [a-z], [^abc].
fn matchBracket(atom: []const u8, ch: u8) bool {
    if (atom.len < 3 or atom[0] != '[') return false;
    const end = atom.len - 1; // skip closing ]
    var i: usize = 1;
    var negate = false;
    if (atom[i] == '^') {
        negate = true;
        i += 1;
    }
    var matched = false;
    while (i < end) {
        // Range: a-z
        if (i + 2 < end and atom[i + 1] == '-') {
            const lo = std.ascii.toLower(atom[i]);
            const hi = std.ascii.toLower(atom[i + 2]);
            const c = std.ascii.toLower(ch);
            if (c >= lo and c <= hi) matched = true;
            i += 3;
        } else {
            if (charEqI(atom[i], ch)) matched = true;
            i += 1;
        }
    }
    return if (negate) !matched else matched;
}

// ── Tests ──

test "literal match" {
    try std.testing.expect(match("hello", "hello world"));
    try std.testing.expect(match("world", "hello world"));
    try std.testing.expect(!match("xyz", "hello world"));
}

test "case insensitive" {
    try std.testing.expect(match("HELLO", "hello world"));
    try std.testing.expect(match("Hello", "HELLO WORLD"));
}

test "dot matches any" {
    try std.testing.expect(match("h.llo", "hello"));
    try std.testing.expect(match("...", "abc"));
    try std.testing.expect(!match("....", "abc"));
}

test "star quantifier" {
    try std.testing.expect(match("he*llo", "hllo"));
    try std.testing.expect(match("he*llo", "hello"));
    try std.testing.expect(match("he*llo", "heeello"));
    try std.testing.expect(match(".*google.*", "www.google.com"));
}

test "plus quantifier" {
    try std.testing.expect(!match("he+llo", "hllo"));
    try std.testing.expect(match("he+llo", "hello"));
    try std.testing.expect(match("he+llo", "heeello"));
}

test "question quantifier" {
    try std.testing.expect(match("colou?r", "color"));
    try std.testing.expect(match("colou?r", "colour"));
    try std.testing.expect(!match("colou?r", "colouur"));
}

test "anchors" {
    try std.testing.expect(match("^hello", "hello world"));
    try std.testing.expect(!match("^world", "hello world"));
    try std.testing.expect(match("world$", "hello world"));
    try std.testing.expect(!match("hello$", "hello world"));
    try std.testing.expect(match("^hello world$", "hello world"));
}

test "bracket expressions" {
    try std.testing.expect(match("[abc]", "a"));
    try std.testing.expect(match("[abc]", "b"));
    try std.testing.expect(!match("[abc]", "d"));
    try std.testing.expect(match("[a-z]", "m"));
    try std.testing.expect(!match("[a-z]", "5"));
    try std.testing.expect(match("[^0-9]", "a"));
    try std.testing.expect(!match("[^0-9]", "5"));
}

test "escape sequences" {
    try std.testing.expect(match("\\d+", "123"));
    try std.testing.expect(!match("^\\d+$", "abc"));
    try std.testing.expect(match("\\w+", "hello_123"));
    try std.testing.expect(match("\\.", "test.com"));
}

test "domain patterns" {
    // Common proxy routing patterns
    try std.testing.expect(match("^ads?\\.", "ad.example.com"));
    try std.testing.expect(match("^ads?\\.", "ads.example.com"));
    try std.testing.expect(!match("^ads?\\.", "admin.example.com"));
    try std.testing.expect(match(".*\\.cn$", "test.cn"));
    try std.testing.expect(match(".*\\.cn$", "www.test.cn"));
    try std.testing.expect(!match(".*\\.cn$", "test.com"));
}

test "empty pattern and text" {
    try std.testing.expect(match("", "anything"));
    try std.testing.expect(match("", ""));
    try std.testing.expect(!match("a", ""));
}
