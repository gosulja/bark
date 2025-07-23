use super::decoders;
use super::decoders::*;
use super::decompiler;
use super::misc;
use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::v_flex;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum ViewMode {
    Linear,
    Hex,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub symbol_type: String,
}

pub struct BarkApp {
    pub input: String,
    pub output: Vec<Instruction>,
    pub decompiled: String,
    pub variables: HashMap<String, Var>,
    pub next_var_id: usize,
    current_view: ViewMode,
    functions: Vec<Function>,
    symbols: Vec<Symbol>,
    selected_function: Option<usize>,
    selected_address: Option<u64>,
    sidebar_visible: bool,
    hex_data: Vec<u8>,
    search_query: String,
    active_tab: usize,
    console_output: Vec<String>,
}

impl BarkApp {
    pub fn new(_window: &mut Window, _cx: &mut Context<Self>) -> Self {
        let mut instance = Self {
            input: String::new(),
            output: Vec::new(),
            decompiled: String::new(),
            variables: HashMap::new(),
            next_var_id: 0,
            current_view: ViewMode::Linear,
            functions: Vec::new(),
            symbols: Vec::new(),
            selected_function: None,
            selected_address: None,
            sidebar_visible: true,
            hex_data: Vec::new(),
            search_query: String::new(),
            active_tab: 0,
            console_output: vec!["bark disassembler init".to_string()],
        };

        instance.load_file();
        instance.analyze_functions();
        instance
    }

    fn parse_bytes(&self, input: &str) -> Result<Vec<u8>, String> {
        let cleaned = input.replace(" ", "").replace("0x", "");
        if cleaned.len() % 2 != 0 {
            return Err("invalid byte input str length".to_string());
        }

        let mut bytes = vec![];
        for i in (0..cleaned.len()).step_by(2) {
            let bstr = &cleaned[i..i + 2];
            match u8::from_str_radix(bstr, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => return Err(format!("invalid hex byte: {}", bstr)),
            }
        }
        Ok(bytes)
    }

    fn load_file(&mut self) {
        match std::fs::read_to_string("input.s") {
            Ok(content) => {
                self.input = content.trim().to_string();
                self.process_input();
                self.console_output
                    .push("loaded input.s successfully".to_string());
            }
            Err(_) => {
                self.console_output
                    .push("err: input.s not found in root directory".to_string());
            }
        }
    }

    fn decode(&self, bytes: &[u8], addr: u64) -> Option<Instruction> {
        if bytes.is_empty() {
            return None;
        }
        get_platform_decoder(bytes, addr)
    }

    pub fn gen_var_name(&mut self) -> String {
        let name = format!("v{}", self.next_var_id);
        self.next_var_id += 1;
        name
    }

    fn analyze_functions(&mut self) {
        /*
            This function is where we'll obviously analyze functions,
            for now, to make it clear just define an entry point func,
            and a few tests (debug)
        */

        let current_func = Function {
            name: "main".to_string(),
            address: 0x400000,
            size: self.output.len(),
            instructions: self.output.clone(),
        };

        self.functions.push(current_func);

        self.functions.push(Function {
            name: "sub_test".to_string(),
            address: 0x410000,
            size: self.output.len(),
            instructions: vec![],
        });

        self.symbols.push(Symbol {
            name: "main".to_string(),
            address: 0x400000,
            symbol_type: "fn".to_string(),
        });
    }

    fn process_input(&mut self) {
        self.output.clear();

        if let Ok(bytes) = self.parse_bytes(&self.input) {
            self.hex_data = bytes.clone();
            let base_addr = 0x400000u64;
            let mut offset = 0;

            while offset < bytes.len() {
                if let Some(inst) = self.decode(&bytes[offset..], base_addr + offset as u64) {
                    offset += inst.bytes.len();
                    self.output.push(inst);
                } else {
                    offset += 1;
                }
            }
        }

        decompiler::decompile(self);
    }

    fn render_sidebar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .w_64()
            .bg(rgb(0x1a1a1a))
            .border_r_1()
            .border_color(rgb(0x383838))
            .child(
                div().p_3().border_b_1().border_color(rgb(0x383838)).child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .text_color(rgb(0xffffff))
                        .child("functions"),
                ),
            )
            .child(
                div()
                    .flex_1()
                    .p_2()
                    .children(self.functions.iter().enumerate().map(|(i, func)| {
                        div()
                            .p_2()
                            .rounded_md()
                            .cursor_pointer()
                            .when(self.selected_function == Some(i), |div| {
                                div.bg(rgb(0x2d2d30))
                            })
                            .hover(|div| div.bg(rgb(0x252526)))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0xdcdcdc))
                                    .child(func.name.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(0x808080))
                                    .child(format!("0x{:08x}", func.address)),
                            )
                    })),
            )
    }

    fn render_main_view(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().child(match self.current_view {
            ViewMode::Linear => self.render_linear_view(cx).into_any_element(),
            ViewMode::Hex => self.render_hex_view(cx).into_any_element(),
        })
    }

    fn render_linear_view(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .size_full()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_1_2()
                    .bg(rgb(0x1e1e1e))
                    .border_r_1()
                    .border_color(rgb(0x383838))
                    .child(
                        div().p_3().border_b_1().border_color(rgb(0x383838)).child(
                            div()
                                .text_sm()
                                .font_weight(FontWeight::NORMAL)
                                .text_color(rgb(0xffffff))
                                .child("disassembly"),
                        ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .font_family("CaskaydiaCove Nerd Font")
                            .text_sm()
                            .child(v_flex().children(self.output.iter().map(|instr| {
                                let line = format!(
                                    "0x{:08x}: {} {}",
                                    instr.addr,
                                    instr.mnemonic,
                                    instr.operands.join(", ")
                                );

                                misc::do_highlight(&line, "asm")
                            }))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_1_2()
                    .bg(rgb(0x1e1e1e))
                    .child(
                        div().p_3().border_b_1().border_color(rgb(0x383838)).child(
                            div()
                                .text_sm()
                                .font_weight(FontWeight::NORMAL)
                                .text_color(rgb(0xffffff))
                                .child("decompiler"),
                        ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .font_family("CaskaydiaCove Nerd Font")
                            .text_sm()
                            .children(self.decompiled.lines().map(|line| {
                                div()
                                    .p_1()
                                    .text_color(rgb(0xdcdcdc))
                                    .child(misc::do_highlight(line, "c"))
                            })),
                    ),
            )
    }

    fn render_hex_view(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(0x1e1e1e))
            .child(
                div().p_3().border_b_1().border_color(rgb(0x383838)).child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(0xffffff))
                        .child("hex view"),
                ),
            )
            .child(
                div()
                    .flex_1()
                    .p_3()
                    .font_family("CaskaydiaCove Nerd Font")
                    .text_sm()
                    .children(self.hex_data.chunks(16).enumerate().map(|(i, chunk)| {
                        div()
                            .flex()
                            .p_1()
                            .child(
                                div()
                                    .w_24()
                                    .text_color(rgb(0x569cd6))
                                    .child(format!("{:08x}:", i * 16)),
                            )
                            .child(
                                div().ml_4().text_color(rgb(0xdcdcdc)).child(
                                    chunk
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" "),
                                ),
                            )
                    })),
            )
    }

    fn render_toolbar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .justify_between()
            .p_3()
            .bg(rgb(0x252526))
            .border_b_1()
            .border_color(rgb(0x383838))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new("reload-btn")
                            .primary()
                            .label("reload")
                            .on_click(cx.listener(|this: &mut BarkApp, _, _, _| {
                                this.load_file();
                            })),
                    )
                    .child(
                        Button::new("linear-view")
                            .when(matches!(self.current_view, ViewMode::Linear), |btn| {
                                btn.primary()
                            })
                            .label("linear")
                            .on_click(cx.listener(|this: &mut BarkApp, _, _, _| {
                                this.current_view = ViewMode::Linear;
                            })),
                    )
                    .child(
                        Button::new("hex-view")
                            .when(matches!(self.current_view, ViewMode::Hex), |btn| {
                                btn.primary()
                            })
                            .label("hex")
                            .on_click(cx.listener(|this: &mut BarkApp, _, _, _| {
                                this.current_view = ViewMode::Hex;
                            })),
                    ),
            )
            .child(
                div().flex().items_center().gap_2().child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(0xffffff))
                        .child("bark disassembler"),
                ),
            )
    }
}

/* Helper for getting platform decoder */
fn get_platform_decoder(bytes: &[u8], addr: u64) -> Option<Instruction> {
    decoders::amd64::decode(bytes, addr)
}

impl Render for BarkApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(0x1e1e1e))
            .text_color(rgb(0xffffff))
            .font_family("CaskaydiaCove Nerd Font")
            .child(self.render_toolbar(cx))
            .child(
                div().flex().flex_1().child(
                    div()
                        .flex()
                        .size_full()
                        .when(self.sidebar_visible, |div| {
                            div.child(self.render_sidebar(cx))
                        })
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .child(div().flex_1().child(self.render_main_view(cx))),
                        ),
                ),
            )
    }
}
