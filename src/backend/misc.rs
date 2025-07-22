use gpui::{Div, ParentElement, Rgba, Styled, div, rgb};
use regex::Regex;

/*
    Highlight a string into an Element.
    `s` being the string to highlight.
    `typ` being the type of highlight, "asm" or "c"
*/
pub fn do_highlight(s: &str, typ: &str) -> Div {
    let mut elems = vec![];
    let mut pos = 0;

    let (patterns, default) = match typ {
        "asm" => (
            vec![
                /* address */
                (Regex::new(r"0x[0-9a-fA-F]+").unwrap(), rgb(0x8be9fd)),
                /* mnemonics */
                (Regex::new(r"\b(mov|push|pop|call|jmp|ret|add|sub|xor|and|or|cmp|test|lea|nop|syscall|int|syscall|ud2|hlt|leave|enter)\b").unwrap(), rgb(0xffb86c)),
                /* registers */
                (Regex::new(r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|xmm0|xmm1|xmm2|xmm3|xmm4|xmm5|xmm6|xmm7)\b").unwrap(), rgb(0xbd93f9)),
                /* mem refs */
                (Regex::new(r"\[.*?\]").unwrap(), rgb(0x50fa7b)),
                /* constants (numbers) */
                (Regex::new(r"\b\d+\b").unwrap(), rgb(0x50fa7b)),
                /* delimiters */
                (Regex::new(r"[,\+\-\*\/]").unwrap(), rgb(0xf8f8f2)),
                /* comments */
                (Regex::new(r";.*").unwrap(), rgb(0x6272a4)),
            ], rgb(0xf8f8f2)
        ),

        "c" => (
            vec![
                /* control flow kws */
                (Regex::new(r"\b(if|else|while|for|return|break|continue|switch|case|default|goto)\b").unwrap(), rgb(0xff79c6)),
                /* types */
                (Regex::new(r"\b(int|int32_t|int64_t|char|void|float|double|long|short|struct|union|enum|typedef|const|static|extern|volatile|signed|unsigned)\b").unwrap(), rgb(0x8be9fd)),
                /* preprocessors */
                (Regex::new(r"#.*").unwrap(), rgb(0xa68ccc)),
                /* bools or null */
                (Regex::new(r"\b(true|false|NULL)\b").unwrap(), rgb(0xbd93f9)),
                /* strings */
                (Regex::new(r#""[^"]*""#).unwrap(), rgb(0xf1fa8c)),
                /* numbers */
                (Regex::new(r"\b\d+(\.\d*)?([eE][+-]?\d+)?\b|0x[0-9a-fA-F]+\b").unwrap(), rgb(0x50fa7b)),
                /* comments */
                (Regex::new(r"//.*").unwrap(), rgb(0x6272a4)),
                /* multi comments */
                (Regex::new(r"/\*[\s\S]*?\*/").unwrap(), rgb(0x6272a4)),
                /* punctuation */
                (Regex::new(r"[(){}\[\];,=+\-*/&|!%<>]").unwrap(), rgb(0xf8f8f2)),
            ], rgb(0xfafaf2)
        ),

        _ => (vec![], rgb(0xf8f8f2)),
    };

    /* highlight string */
    let hstr = s;
    /* process each char */
    while pos < hstr.len() {
        let remaining = &hstr[pos..];

        /* start, len, color */
        let mut tok_match: Option<(usize, usize, Rgba)> = None;

        for (regex, color) in &patterns {
            if let Some(m) = regex.find(remaining) {
                if m.start() == 0 {
                    if tok_match.is_none() || m.len() > tok_match.unwrap().1 {
                        tok_match = Some((m.start(), m.len(), *color));
                    }
                }
            }
        }

        /* add the matches token to the elements */
        if let Some((s_idx, len, color)) = tok_match {
            elems.push(
                div()
                    .child(remaining[s_idx..s_idx + len].to_string())
                    .text_color(color),
            );
            pos += s_idx + len;
        } else {
            /* no pattern? then find the next potential token match, add unhighlighted between. */
            let mut next_tok_start = remaining.len();
            /* iterate over each pattern */
            for (regex, _) in &patterns {
                /* if we find a pattern in the remaning string, move onto the next token */
                if let Some(m) = regex.find(remaining) {
                    if m.start() < next_tok_start {
                        next_tok_start = m.start();
                    }
                }
            }

            /* push the string into the elems vector to be rendered (with default txt color) */
            elems.push(
                div()
                    .child(remaining[..next_tok_start].to_string())
                    .text_color(default),
            );
            pos += next_tok_start;
        }
    }

    div().flex().flex_row().children(elems)
}
