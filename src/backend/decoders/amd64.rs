use super::Instruction;
use std::collections::HashMap;

const REG8: &[&str] = &[
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b",
    "r14b", "r15b",
];
const REG16: &[&str] = &[
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w",
];
const REG32: &[&str] = &[
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d",
];
const REG64: &[&str] = &[
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const ALU_OPS: &[&str] = &["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];

#[derive(Default)]
pub struct VariableRecovery {
    stack_vars: HashMap<i64, String>,
    reg_vars: HashMap<String, String>,
    strings: HashMap<u64, String>,
    next_var_id: u32,
}

impl VariableRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_string(&mut self, addr: u64, data: &[u8]) {
        if let Some(s) = extract_string(data) {
            self.strings.insert(addr, s);
        }
    }

    pub fn add_string_section(&mut self, base_addr: u64, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            if let Some((string, len)) = extract_string_at(&data[pos..]) {
                if len > 3 {
                    self.strings.insert(base_addr + pos as u64, string);
                }
                pos += len.max(1);
            } else {
                pos += 1;
            }
        }
    }

    fn get_stack_var(&mut self, offset: i64) -> String {
        if let Some(var) = self.stack_vars.get(&offset) {
            var.clone()
        } else {
            let var_name = if offset < 0 {
                format!("var_{:x}", (-offset) as u32)
            } else {
                format!("arg_{:x}", offset as u32)
            };
            self.stack_vars.insert(offset, var_name.clone());
            var_name
        }
    }

    fn get_reg_var(&mut self, reg: &str) -> String {
        if let Some(var) = self.reg_vars.get(reg) {
            var.clone()
        } else {
            let var_name = format!("v{}", self.next_var_id);
            self.next_var_id += 1;
            self.reg_vars.insert(reg.to_string(), var_name.clone());
            var_name
        }
    }

    pub fn process_operand(&mut self, operand: &str, _addr: u64) -> String {
        if operand.starts_with("0x") {
            if let Ok(val) = u64::from_str_radix(&operand[2..], 16) {
                if let Some(s) = self.strings.get(&val) {
                    return format!("\"{}\"", s);
                }
                if val > 0x400000 && val < 0x800000 {
                    return format!("str_{:x}", val);
                }
            }
            return operand.to_string();
        }

        if operand.contains('[') {
            return self.process_memory_operand(operand);
        }

        if REG64.contains(&operand)
            || REG32.contains(&operand)
            || REG16.contains(&operand)
            || REG8.contains(&operand)
        {
            return self.get_reg_var(operand);
        }

        operand.to_string()
    }

    fn process_memory_operand(&mut self, operand: &str) -> String {
        if operand.contains("rbp") || operand.contains("ebp") {
            if let Some(offset_str) = operand
                .strip_prefix("[rbp")
                .or_else(|| operand.strip_prefix("[ebp"))
            {
                if let Some(offset_str) = offset_str.strip_suffix("]") {
                    if offset_str.is_empty() {
                        return self.get_stack_var(0);
                    }
                    if let Ok(offset) = offset_str.parse::<i64>() {
                        return self.get_stack_var(offset);
                    }
                }
            }
        }
        operand.to_string()
    }
}

#[derive(Default, Clone)]
struct Prefixes {
    op_size: bool,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    start: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            start: 0,
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.pos >= self.bytes.len() {
            None
        } else {
            let val = self.bytes[self.pos];
            self.pos += 1;
            Some(val)
        }
    }

    fn peek_u8(&self) -> Option<u8> {
        if self.pos >= self.bytes.len() {
            None
        } else {
            Some(self.bytes[self.pos])
        }
    }

    fn read_imm(&mut self, size: usize) -> Option<u64> {
        if self.pos + size > self.bytes.len() {
            return None;
        }
        let val = match size {
            1 => self.bytes[self.pos] as u64,
            2 => u16::from_le_bytes(self.bytes[self.pos..self.pos + 2].try_into().ok()?) as u64,
            4 => u32::from_le_bytes(self.bytes[self.pos..self.pos + 4].try_into().ok()?) as u64,
            8 => u64::from_le_bytes(self.bytes[self.pos..self.pos + 8].try_into().ok()?),
            _ => return None,
        };
        self.pos += size;
        Some(val)
    }

    fn consume_prefixes(&mut self) -> Option<Prefixes> {
        let mut prefixes = Prefixes::default();
        self.start = self.pos;

        while let Some(byte) = self.peek_u8() {
            match byte {
                0x66 => {
                    prefixes.op_size = true;
                    self.pos += 1;
                }
                b if (b & 0xF0) == 0x40 => {
                    prefixes.rex_w = (b & 0x08) != 0;
                    prefixes.rex_r = (b & 0x04) != 0;
                    prefixes.rex_x = (b & 0x02) != 0;
                    prefixes.rex_b = (b & 0x01) != 0;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        Some(prefixes)
    }

    fn get_reg_size(&self, prefixes: &Prefixes) -> (usize, usize) {
        match (prefixes.op_size, prefixes.rex_w) {
            (true, _) => (2, 16),
            (false, true) => (8, 64),
            _ => (4, 32),
        }
    }

    fn get_register(&self, reg_id: usize, size: usize, rex_ext: bool) -> Option<&'static str> {
        let id = reg_id + if rex_ext { 8 } else { 0 };
        match size {
            8 => REG8.get(id).copied(),
            16 => REG16.get(id).copied(),
            32 => REG32.get(id).copied(),
            64 => REG64.get(id).copied(),
            _ => None,
        }
    }

    fn decode_modrm(&mut self, prefixes: &Prefixes) -> Option<(String, usize)> {
        let modrm = self.read_u8()?;
        let mode = (modrm >> 6) & 0x03;
        // let reg = (modrm >> 3) & 0x07;
        let rm = modrm & 0x07;

        let (_, reg_size) = self.get_reg_size(prefixes);

        match mode {
            0b11 => {
                let reg_name = self.get_register(rm as usize, reg_size, prefixes.rex_b)?;
                Some((reg_name.to_string(), 1))
            }
            0b00 | 0b01 | 0b10 => {
                let disp_size = match mode {
                    0b00 => {
                        if rm == 5 {
                            4
                        } else {
                            0
                        }
                    }
                    0b01 => 1,
                    0b10 => 4,
                    _ => unreachable!(),
                };

                if rm == 4 {
                    let sib = self.read_u8()?;
                    let scale = (sib >> 6) & 0x03;
                    let index = (sib >> 3) & 0x07;
                    let base = sib & 0x07;

                    let mut operand = String::from("[");

                    if base != 5 || mode != 0 {
                        let base_reg = self.get_register(base as usize, 64, prefixes.rex_b)?;
                        operand.push_str(base_reg);
                    }

                    if index != 4 {
                        if !operand.ends_with('[') {
                            operand.push('+');
                        }
                        let index_reg = self.get_register(index as usize, 64, prefixes.rex_x)?;
                        operand.push_str(index_reg);
                        if scale > 0 {
                            operand.push_str(&format!("*{}", 1 << scale));
                        }
                    }

                    if disp_size > 0 {
                        let disp = match disp_size {
                            1 => self.read_imm(1)? as i8 as i64,
                            4 => self.read_imm(4)? as i32 as i64,
                            _ => return None,
                        };
                        if disp != 0 {
                            if disp > 0 && !operand.ends_with('[') {
                                operand.push('+');
                            }
                            operand.push_str(&disp.to_string());
                        }
                    }
                    operand.push(']');
                    Some((operand, disp_size + 1))
                } else {
                    let base_reg = if rm == 5 && mode == 0 {
                        "rip".to_string()
                    } else {
                        self.get_register(rm as usize, 64, prefixes.rex_b)?
                            .to_string()
                    };

                    let mut operand = format!("[{}", base_reg);

                    if disp_size > 0 {
                        let disp = match disp_size {
                            1 => self.read_imm(1)? as i8 as i64,
                            4 => self.read_imm(4)? as i32 as i64,
                            _ => return None,
                        };
                        if disp != 0 {
                            if disp > 0 {
                                operand.push('+');
                            }
                            operand.push_str(&disp.to_string());
                        }
                    }
                    operand.push(']');
                    Some((operand, disp_size))
                }
            }
            _ => None,
        }
    }

    fn build_instruction(&self, mnemonic: &str, operands: Vec<String>, addr: u64) -> Instruction {
        Instruction {
            addr,
            bytes: self.bytes[self.start..self.pos].to_vec(),
            mnemonic: mnemonic.to_string(),
            operands,
        }
    }
}

pub fn decode(bytes: &[u8], addr: u64) -> Option<Instruction> {
    let mut cursor = Cursor::new(bytes);
    cursor.start = 0;
    let prefixes = cursor.consume_prefixes()?;
    let opc = cursor.read_u8()?;

    match opc {
        0xB0..=0xBF => decode_mov_reg_imm(&mut cursor, opc, &prefixes, addr),
        0xC6 | 0xC7 => decode_mov_rm_imm(&mut cursor, opc, &prefixes, addr),
        0x80..=0x83 => decode_alu_rm_imm(&mut cursor, opc, &prefixes, addr),
        0x50..=0x5F => decode_push_pop(&mut cursor, opc, &prefixes, addr),
        0xC3 => Some(cursor.build_instruction("ret", vec![], addr)),
        0x89 | 0x8B => decode_mov_reg_rm(&mut cursor, opc, &prefixes, addr),
        0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 | 0x39 => {
            decode_alu_rm_reg(&mut cursor, opc, &prefixes, addr)
        }
        _ => None,
    }
}

fn decode_mov_reg_imm(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let is_wide = (opc & 0x08) != 0;
    let reg_id = (opc & 0x07) as usize;

    let (imm_size, reg_size) = if is_wide {
        let (op_size, reg_size) = cursor.get_reg_size(prefixes);
        (if reg_size == 64 { 8 } else { op_size }, reg_size)
    } else {
        (1, 8)
    };

    let reg = cursor.get_register(reg_id, reg_size, prefixes.rex_b)?;
    let imm = cursor.read_imm(imm_size)?;

    Some(cursor.build_instruction("mov", vec![reg.to_string(), format!("0x{:x}", imm)], addr))
}

fn decode_mov_rm_imm(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let (operand, _) = cursor.decode_modrm(prefixes)?;
    let imm_size = match opc {
        0xC6 => 1,
        0xC7 => {
            let (op_size, _) = cursor.get_reg_size(prefixes);
            op_size.min(4)
        }
        _ => return None,
    };

    let imm = cursor.read_imm(imm_size)?;
    Some(cursor.build_instruction("mov", vec![operand, format!("0x{:x}", imm)], addr))
}

fn decode_mov_reg_rm(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let modrm = cursor.peek_u8()?;
    let reg_field = ((modrm >> 3) & 0x07) as usize;
    let (_, reg_size) = cursor.get_reg_size(prefixes);
    let reg = cursor.get_register(reg_field, reg_size, prefixes.rex_r)?;

    let (rm_operand, _) = cursor.decode_modrm(prefixes)?;

    match opc {
        0x89 => Some(cursor.build_instruction("mov", vec![rm_operand, reg.to_string()], addr)),
        0x8B => Some(cursor.build_instruction("mov", vec![reg.to_string(), rm_operand], addr)),
        _ => None,
    }
}

fn decode_alu_rm_imm(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let modrm = cursor.peek_u8()?;
    let alu_op = ((modrm >> 3) & 0x07) as usize;
    let mnemonic = ALU_OPS.get(alu_op)?;

    let (operand, _) = cursor.decode_modrm(prefixes)?;

    let imm_size = match opc {
        0x80 | 0x82 => 1,
        0x81 => {
            let (op_size, _) = cursor.get_reg_size(prefixes);
            op_size.min(4)
        }
        0x83 => 1,
        _ => return None,
    };

    let imm = cursor.read_imm(imm_size)?;
    Some(cursor.build_instruction(mnemonic, vec![operand, format!("0x{:x}", imm)], addr))
}

fn decode_alu_rm_reg(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let alu_idx = (opc >> 3) & 0x07;
    let mnemonic = ALU_OPS.get(alu_idx as usize)?;

    let modrm = cursor.peek_u8()?;
    let reg_field = ((modrm >> 3) & 0x07) as usize;
    let (_, reg_size) = cursor.get_reg_size(prefixes);
    let reg = cursor.get_register(reg_field, reg_size, prefixes.rex_r)?;

    let (rm_operand, _) = cursor.decode_modrm(prefixes)?;

    Some(cursor.build_instruction(mnemonic, vec![rm_operand, reg.to_string()], addr))
}

fn decode_push_pop(
    cursor: &mut Cursor,
    opc: u8,
    prefixes: &Prefixes,
    addr: u64,
) -> Option<Instruction> {
    let is_pop = opc >= 0x58;
    let reg_id = (opc & 0x07) as usize;
    let (_, reg_size) = cursor.get_reg_size(prefixes);

    let reg = cursor.get_register(reg_id, reg_size.max(32), prefixes.rex_b)?;
    let mnemonic = if is_pop { "pop" } else { "push" };

    Some(cursor.build_instruction(mnemonic, vec![reg.to_string()], addr))
}

fn extract_string(data: &[u8]) -> Option<String> {
    extract_string_at(data).map(|(s, _)| s)
}

fn extract_string_at(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() {
        return None;
    }

    let mut end = 0;
    let mut printable_count = 0;

    for &byte in data {
        if byte == 0 {
            break;
        }
        if byte >= 32 && byte <= 126 {
            printable_count += 1;
        }
        end += 1;
        if end > 1024 {
            break;
        }
    }

    if end < 3 || (printable_count as f32) / (end as f32) < 0.8 {
        return None;
    }

    match String::from_utf8(data[..end].to_vec()) {
        Ok(s) => Some((s, end + 1)),
        Err(_) => None,
    }
}

pub fn decode_with_vr(bytes: &[u8], addr: u64, vr: &mut VariableRecovery) -> Option<Instruction> {
    if let Some(mut instr) = decode(bytes, addr) {
        instr.operands = instr
            .operands
            .into_iter()
            .map(|op| vr.process_operand(&op, addr))
            .collect();
        Some(instr)
    } else {
        None
    }
}
