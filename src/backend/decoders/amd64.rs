use super::Instruction;

pub fn decode(bytes: &[u8], addr: u64) -> Option<Instruction> {
    /*
        references: https://wiki.osdev.org/x86-64_instruction_encoding
        supports:
        - mov r8, imm8               (b0-b7)
        - mov r16, imm16             (66 b8-bf)
        - mov r32, imm32             (b8-bf)
        - movabs r64, imm64          (48 b8-bf)
        - mov r/m8, imm8             (c6 /0)
        - mov r/m16, imm16           (66 c7 /0)
        - mov r/m32, imm32           (c7 /0)
        - mov r/m64, imm32           (48 c7 /0)
        - add/or/adc/sbb/and/sub/xor/cmp r/m, imm8/16/32
          (80-83, 66 83, 66 81, f6-f7, etc.)
        - push/pop r64               (50-5f, 40-5f)
        - ret                        (c3)
    */

    let mut idx = 0;

    // consume prefixes
    let mut p66 = false;
    let pref_start = idx; /* dont need mut */
    while idx < bytes.len() {
        match bytes[idx] {
            0x66 => p66 = true,
            b if (b & 0xF0) == 0x40 => { /* rex */ }
            _ => break,
        }
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }
    let rex = if idx > pref_start {
        Some(bytes[pref_start])
    } else {
        None
    };

    // operand size
    let (op_size, reg_size) = match (p66, rex) {
        (true, _) => (2, 16),
        (false, Some(r)) if (r & 0x08) != 0 => (8, 64),
        _ => (4, 32),
    };

    // helpers for imm reading
    macro_rules! read_imm {
        ($sz:expr) => {{
            let need = idx + $sz;
            if bytes.len() < need {
                return None;
            }
            match $sz {
                1 => bytes[idx] as u64,
                2 => u16::from_le_bytes(bytes[idx..need].try_into().unwrap()) as u64,
                4 => u32::from_le_bytes(bytes[idx..need].try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(bytes[idx..need].try_into().unwrap()),
                _ => unreachable!(),
            }
        }};
    }

    let opc = bytes[idx];
    idx += 1;

    // 1) mov r, imm
    if (0xB0..=0xBF).contains(&opc) {
        let is_wide = (opc & 0x08) != 0;
        let r_id = (opc & 0x07) as usize;

        let (reg, imm_bytes) = match (is_wide, reg_size) {
            (false, _) => (["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][r_id], 1),
            (true, 16) => (["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][r_id], 2),
            (true, 32) => (
                ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
                4,
            ),
            (true, 64) => (
                ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
                8,
            ),
            _ => return None,
        };

        let imm = read_imm!(imm_bytes);
        return Some(Instruction {
            addr,
            bytes: bytes[..idx + imm_bytes].to_vec(),
            mnemonic: "mov".into(),
            operands: vec![reg.into(), format!("0x{:x}", imm)],
        });
    }

    // 2) mov r/m, imm   (c6 /0 or c7 /0)
    if opc == 0xC6 || opc == 0xC7 {
        if idx >= bytes.len() {
            return None;
        }
        let modrm = bytes[idx];
        idx += 1;
        if (modrm & 0xC0) != 0xC0 {
            return None;
        } // reg-direct only
        let r_id = (modrm & 0x07) as usize;

        let (reg, imm_bytes) = match opc {
            0xC6 => (["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][r_id], 1),
            0xC7 => match reg_size {
                16 => (["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][r_id], 2),
                32 => (
                    ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
                    4,
                ),
                64 => (
                    ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
                    4,
                ),
                _ => return None,
            },
            _ => unreachable!(),
        };

        let imm = read_imm!(imm_bytes);
        return Some(Instruction {
            addr,
            bytes: bytes[..idx + imm_bytes].to_vec(),
            mnemonic: "mov".into(),
            operands: vec![reg.into(), format!("0x{:x}", imm)],
        });
    }

    // 3) alu r/m, imm  (80-83, 81, f6-f7)
    /*
        we dont need the tuple assignment
    */
    match opc {
        0x80 | 0x82 => {
            if idx >= bytes.len() {
                return None;
            }
            let modrm = bytes[idx];
            idx += 1;
            if (modrm & 0xC0) != 0xC0 {
                return None;
            }
            let r_id = (modrm & 0x07) as usize;
            let reg = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][r_id];
            let alu = (modrm >> 3) & 0x07;
            let mn = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][alu as usize];
            let imm = read_imm!(1);
            return Some(Instruction {
                addr,
                bytes: bytes[..idx + 1].to_vec(),
                mnemonic: mn.into(),
                operands: vec![reg.into(), format!("0x{:x}", imm)],
            });
        }
        0x81 => {
            if idx >= bytes.len() {
                return None;
            }
            let modrm = bytes[idx];
            idx += 1;
            if (modrm & 0xC0) != 0xC0 {
                return None;
            }
            let r_id = (modrm & 0x07) as usize;
            let reg = match reg_size {
                16 => ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][r_id],
                32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
                64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
                _ => return None,
            };
            let alu = (modrm >> 3) & 0x07;
            let mn = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][alu as usize];
            let imm = read_imm!(op_size.min(4));
            return Some(Instruction {
                addr,
                bytes: bytes[..idx + op_size.min(4)].to_vec(),
                mnemonic: mn.into(),
                operands: vec![reg.into(), format!("0x{:x}", imm)],
            });
        }
        0x83 => {
            if idx >= bytes.len() {
                return None;
            }
            let modrm = bytes[idx];
            idx += 1;
            if (modrm & 0xC0) != 0xC0 {
                return None;
            }
            let r_id = (modrm & 0x07) as usize;
            let reg = match reg_size {
                16 => ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][r_id],
                32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
                64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
                _ => return None,
            };
            let alu = (modrm >> 3) & 0x07;
            let mn = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][alu as usize];
            let imm = read_imm!(1);
            return Some(Instruction {
                addr,
                bytes: bytes[..idx + 1].to_vec(),
                mnemonic: mn.into(),
                operands: vec![reg.into(), format!("0x{:x}", imm)],
            });
        }
        _ => {}
    }

    // 4) push reg
    if (0x50..=0x57).contains(&opc) {
        let r_id = (opc - 0x50) as usize;
        let reg = match reg_size {
            32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
            64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
            _ => return None,
        };
        return Some(Instruction {
            addr,
            bytes: bytes[..idx].to_vec(),
            mnemonic: "push".into(),
            operands: vec![reg.into()],
        });
    }

    // 5) pop reg
    if (0x58..=0x5F).contains(&opc) {
        let r_id = (opc - 0x58) as usize;
        let reg = match reg_size {
            32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
            64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
            _ => return None,
        };
        return Some(Instruction {
            addr,
            bytes: bytes[..idx].to_vec(),
            mnemonic: "pop".into(),
            operands: vec![reg.into()],
        });
    }

    // 6) ret
    if opc == 0xC3 {
        return Some(Instruction {
            addr,
            bytes: bytes[..idx].to_vec(),
            mnemonic: "ret".into(),
            operands: vec![],
        });
    }

    None
}
