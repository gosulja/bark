use super::Instruction;
use std::collections::HashMap;

const REGS: &[&str] = &[
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr",
    "pc",
];
const CONDITIONS: &[&str] = &[
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
];

#[derive(Default)]
pub struct VariableRecovery {
    stack_vars: HashMap<i32, String>,
    reg_vars: HashMap<String, String>,
    strings: HashMap<u32, String>,
    next_var_id: u32,
}

impl VariableRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_string(&mut self, addr: u32, data: &[u8]) {
        if let Some(s) = extract_string(data) {
            self.strings.insert(addr, s);
        }
    }

    pub fn add_string_section(&mut self, base_addr: u32, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            if let Some((string, len)) = extract_string_at(&data[pos..]) {
                if len > 3 {
                    self.strings.insert(base_addr + pos as u32, string);
                }
                pos += len.max(1);
            } else {
                pos += 1;
            }
        }
    }

    fn get_stack_var(&mut self, offset: i32) -> String {
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

    pub fn process_operand(&mut self, operand: &str, addr: u32) -> String {
        if operand.starts_with("0x") {
            if let Ok(val) = u32::from_str_radix(&operand[2..], 16) {
                if let Some(s) = self.strings.get(&val) {
                    return format!("\"{}\"", s);
                }
                if val > 0x8000 {
                    return format!("str_{:x}", val);
                }
            }
            return operand.to_string();
        }

        if operand.contains('[') {
            return self.process_memory_operand(operand);
        }

        if REGS.contains(&operand) {
            return self.get_reg_var(operand);
        }

        operand.to_string()
    }

    fn process_memory_operand(&mut self, operand: &str) -> String {
        if operand.contains("sp") {
            if let Some(inner) = operand
                .strip_prefix("[sp")
                .and_then(|s| s.strip_suffix("]"))
            {
                if inner.is_empty() {
                    return self.get_stack_var(0);
                }
                if let Some(offset_str) = inner.strip_prefix(", #") {
                    if let Ok(offset) = offset_str.parse::<i32>() {
                        return self.get_stack_var(offset);
                    }
                }
            }
        }
        operand.to_string()
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.bytes.len() {
            None
        } else {
            let val = u32::from_le_bytes(self.bytes[self.pos..self.pos + 4].try_into().ok()?);
            self.pos += 4;
            Some(val)
        }
    }

    fn build_instruction(&self, mnemonic: &str, operands: Vec<String>, addr: u32) -> Instruction {
        Instruction {
            addr: addr as u64,
            bytes: self.bytes[..self.pos].to_vec(),
            mnemonic: mnemonic.to_string(),
            operands,
        }
    }
}

pub fn decode(bytes: &[u8], addr: u32) -> Option<Instruction> {
    if bytes.len() < 4 {
        return None;
    }

    let mut cursor = Cursor::new(bytes);
    let instr = cursor.read_u32()?;

    let cond = (instr >> 28) & 0xf;
    let op_type = (instr >> 25) & 0x7;

    match op_type {
        0b000 => decode_data_processing(&mut cursor, instr, addr),
        0b001 => decode_immediate(&mut cursor, instr, addr),
        0b010 => decode_load_store(&mut cursor, instr, addr),
        0b100 => decode_load_store_multiple(&mut cursor, instr, addr),
        0b101 => decode_branch(&mut cursor, instr, addr),
        _ => None,
    }
}

fn decode_data_processing(cursor: &mut Cursor, instr: u32, addr: u32) -> Option<Instruction> {
    let opcode = (instr >> 21) & 0xf;
    let s = (instr >> 20) & 1;
    let rn = (instr >> 16) & 0xf;
    let rd = (instr >> 12) & 0xf;
    let cond = (instr >> 28) & 0xf;

    let mnemonic = match opcode {
        0x0 => "and",
        0x1 => "eor",
        0x2 => "sub",
        0x3 => "rsb",
        0x4 => "add",
        0x5 => "adc",
        0x6 => "sbc",
        0x7 => "rsc",
        0x8 => "tst",
        0x9 => "teq",
        0xa => "cmp",
        0xb => "cmn",
        0xc => "orr",
        0xd => "mov",
        0xe => "bic",
        0xf => "mvn",
        _ => return None,
    };

    let cond_suffix = if cond != 14 {
        CONDITIONS[cond as usize]
    } else {
        ""
    };
    let s_suffix = if s == 1 && !matches!(opcode, 0x8..=0xb) {
        "s"
    } else {
        ""
    };
    let full_mnemonic = format!("{}{}{}", mnemonic, cond_suffix, s_suffix);

    let rd_name = REGS[rd as usize];
    let rn_name = REGS[rn as usize];

    let operand2 = decode_operand2(instr);

    let operands = match opcode {
        0x8..=0xb => vec![rn_name.to_string(), operand2],
        0xd | 0xf => vec![rd_name.to_string(), operand2],
        _ => vec![rd_name.to_string(), rn_name.to_string(), operand2],
    };

    Some(cursor.build_instruction(&full_mnemonic, operands, addr))
}

fn decode_immediate(cursor: &mut Cursor, instr: u32, addr: u32) -> Option<Instruction> {
    let opcode = (instr >> 21) & 0xf;
    let s = (instr >> 20) & 1;
    let rn = (instr >> 16) & 0xf;
    let rd = (instr >> 12) & 0xf;
    let imm = instr & 0xfff;
    let cond = (instr >> 28) & 0xf;

    let mnemonic = match opcode {
        0x0 => "and",
        0x1 => "eor",
        0x2 => "sub",
        0x3 => "rsb",
        0x4 => "add",
        0x5 => "adc",
        0x6 => "sbc",
        0x7 => "rsc",
        0x8 => "tst",
        0x9 => "teq",
        0xa => "cmp",
        0xb => "cmn",
        0xc => "orr",
        0xd => "mov",
        0xe => "bic",
        0xf => "mvn",
        _ => return None,
    };

    let cond_suffix = if cond != 14 {
        CONDITIONS[cond as usize]
    } else {
        ""
    };
    let s_suffix = if s == 1 && !matches!(opcode, 0x8..=0xb) {
        "s"
    } else {
        ""
    };
    let full_mnemonic = format!("{}{}{}", mnemonic, cond_suffix, s_suffix);

    let rd_name = REGS[rd as usize];
    let rn_name = REGS[rn as usize];
    let imm_str = format!("0x{:x}", imm);

    let operands = match opcode {
        0x8..=0xb => vec![rn_name.to_string(), imm_str],
        0xd | 0xf => vec![rd_name.to_string(), imm_str],
        _ => vec![rd_name.to_string(), rn_name.to_string(), imm_str],
    };

    Some(cursor.build_instruction(&full_mnemonic, operands, addr))
}

fn decode_load_store(cursor: &mut Cursor, instr: u32, addr: u32) -> Option<Instruction> {
    let l = (instr >> 20) & 1;
    let b = (instr >> 22) & 1;
    let u = (instr >> 23) & 1;
    let p = (instr >> 24) & 1;
    let w = (instr >> 21) & 1;
    let rn = (instr >> 16) & 0xf;
    let rd = (instr >> 12) & 0xf;
    let cond = (instr >> 28) & 0xf;

    let base_mnemonic = if l == 1 { "ldr" } else { "str" };
    let b_suffix = if b == 1 { "b" } else { "" };
    let cond_suffix = if cond != 14 {
        CONDITIONS[cond as usize]
    } else {
        ""
    };
    let mnemonic = format!("{}{}{}", base_mnemonic, b_suffix, cond_suffix);

    let rd_name = REGS[rd as usize];
    let rn_name = REGS[rn as usize];

    let addressing = if (instr >> 25) & 1 == 0 {
        let offset = instr & 0xfff;
        if offset == 0 {
            format!("[{}]", rn_name)
        } else {
            let sign = if u == 1 { "" } else { "-" };
            if p == 1 {
                format!("[{}, #{}0x{:x}]", rn_name, sign, offset)
            } else {
                format!("[{}], #{}0x{:x}", rn_name, sign, offset)
            }
        }
    } else {
        let rm = instr & 0xf;
        let rm_name = REGS[rm as usize];
        let sign = if u == 1 { "" } else { "-" };
        if p == 1 {
            format!("[{}, {}{}]", rn_name, sign, rm_name)
        } else {
            format!("[{}], {}{}", rn_name, sign, rm_name)
        }
    };

    Some(cursor.build_instruction(&mnemonic, vec![rd_name.to_string(), addressing], addr))
}

fn decode_load_store_multiple(cursor: &mut Cursor, instr: u32, addr: u32) -> Option<Instruction> {
    let l = (instr >> 20) & 1;
    let s = (instr >> 22) & 1;
    let w = (instr >> 21) & 1;
    let u = (instr >> 23) & 1;
    let p = (instr >> 24) & 1;
    let rn = (instr >> 16) & 0xf;
    let reg_list = instr & 0xffff;
    let cond = (instr >> 28) & 0xf;

    let base_mnemonic = if l == 1 { "ldm" } else { "stm" };
    let mode = match (p, u) {
        (0, 0) => "da",
        (0, 1) => "ia",
        (1, 0) => "db",
        (1, 1) => "ib",
        _ => "",
    };
    let cond_suffix = if cond != 14 {
        CONDITIONS[cond as usize]
    } else {
        ""
    };
    let mnemonic = format!("{}{}{}", base_mnemonic, mode, cond_suffix);

    let rn_name = REGS[rn as usize];
    let w_suffix = if w == 1 { "!" } else { "" };
    let base_reg = format!("{}{}", rn_name, w_suffix);

    let mut regs = Vec::new();
    for i in 0..16 {
        if (reg_list >> i) & 1 == 1 {
            regs.push(REGS[i].to_string());
        }
    }
    let reg_str = format!("{{{}}}", regs.join(", "));

    Some(cursor.build_instruction(&mnemonic, vec![base_reg, reg_str], addr))
}

fn decode_branch(cursor: &mut Cursor, instr: u32, addr: u32) -> Option<Instruction> {
    let l = (instr >> 24) & 1;
    let offset = (instr & 0xffffff) << 2;
    let cond = (instr >> 28) & 0xf;

    let base_mnemonic = if l == 1 { "bl" } else { "b" };
    let cond_suffix = if cond != 14 {
        CONDITIONS[cond as usize]
    } else {
        ""
    };
    let mnemonic = format!("{}{}", base_mnemonic, cond_suffix);

    let sign_extended = if offset & 0x2000000 != 0 {
        offset | 0xfc000000
    } else {
        offset
    };

    let target = addr.wrapping_add(8).wrapping_add(sign_extended);
    let target_str = format!("0x{:x}", target);

    Some(cursor.build_instruction(&mnemonic, vec![target_str], addr))
}

fn decode_operand2(instr: u32) -> String {
    if (instr >> 25) & 1 == 1 {
        let imm = instr & 0xff;
        let rot = ((instr >> 8) & 0xf) * 2;
        let rotated = imm.rotate_right(rot);
        format!("0x{:x}", rotated)
    } else {
        let rm = instr & 0xf;
        let shift_type = (instr >> 5) & 0x3;
        let shift_amount = (instr >> 7) & 0x1f;

        let rm_name = REGS[rm as usize];

        if shift_amount == 0 {
            rm_name.to_string()
        } else {
            let shift_name = match shift_type {
                0 => "lsl",
                1 => "lsr",
                2 => "asr",
                3 => "ror",
                _ => "",
            };
            format!("{}, {} #{}", rm_name, shift_name, shift_amount)
        }
    }
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

pub fn decode_with_vr(bytes: &[u8], addr: u32, vr: &mut VariableRecovery) -> Option<Instruction> {
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
