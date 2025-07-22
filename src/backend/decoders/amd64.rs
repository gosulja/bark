use super::Instruction;

pub fn decode(bytes: &[u8], addr: u64) -> Option<Instruction> {
    /*
        references: https://wiki.osdev.org/x86-64_instruction_encoding
        we now handle:
        - 32-bit mov r32, imm32
        - 64-bit movabs r64, imm64
        - 64-bit mov r/m64, imm32 (modrm form, reg-to-reg only)
        - 8-bit mov r8, imm8
        - 16-bit mov r16, imm16 (with 0x66 prefix)
    */

    // helper: consume any legacy prefix in group-3 (0x66)
    let mut idx = 0;
    let mut p66 = false;
    while idx < bytes.len() {
        match bytes[idx] {
            0x66 => {
                p66 = true;
                idx += 1;
            }
            _ => break,
        }
    }
    if idx >= bytes.len() {
        return None;
    }

    // helper: check for rex prefix
    let rex = if bytes[idx] & 0xF0 == 0x40 {
        let r = bytes[idx];
        idx += 1;
        if idx >= bytes.len() {
            return None;
        }
        Some(r)
    } else {
        None
    };

    // decide operand size
    let (op_size, reg_size) = match (p66, rex) {
        (true, _) => (2, 16),                           // 0x66 prefix => 16-bit
        (false, Some(r)) if (r & 0x08) != 0 => (8, 64), // rex.w => 64-bit
        _ => (4, 32),                                   // default 32-bit
    };

    // grab the opcode byte
    let opc = bytes[idx];
    idx += 1;

    // mov r, imm  (b8+rd encoding)
    if (0xB8..=0xBF).contains(&opc) {
        let r_id = (opc & 0x07) as usize;
        let reg = match reg_size {
            8 => ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][r_id],
            16 => ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][r_id],
            32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
            64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
            _ => unreachable!(),
        };

        let imm_bytes = match reg_size {
            64 => 8, // movabs imm64
            _ => op_size,
        };

        let need = idx + imm_bytes;
        if bytes.len() < need {
            return None;
        }

        /*
            Previous immediate value calculation used "reg_size" instead of "imm_bytes",
            which caused a panic with 16 bit mov instructions,
            this should handle it correctly.
        */
        let imm = match imm_bytes {
            8 => u64::from_le_bytes(bytes[idx..need].try_into().unwrap()),
            4 => u32::from_le_bytes(bytes[idx..need].try_into().unwrap()) as u64,
            2 => u16::from_le_bytes(bytes[idx..need].try_into().unwrap()) as u64,
            1 => bytes[idx] as u64,
            _ => {
                eprintln!("unexpected imm bytes: {}", imm_bytes);
                return None;
            }
        };

        return Some(Instruction {
            addr,
            bytes: bytes[..need].to_vec(),
            mnemonic: "mov".into(),
            operands: vec![reg.into(), format!("0x{:x}", imm)],
        });
    }

    // mov r/m, imm  (c7 /0 encoding)
    if opc == 0xC7 {
        if idx >= bytes.len() {
            return None;
        }
        let modrm = bytes[idx];
        idx += 1;

        // we only handle the simple reg-direct case (mod = 11)
        if (modrm & 0xC0) != 0xC0 {
            return None;
        }

        let r_id = (modrm & 0x07) as usize;
        let reg = match reg_size {
            32 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][r_id],
            64 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][r_id],
            _ => return None, // 16/8 not available via c7
        };

        let need = idx + 4;
        if bytes.len() < need {
            return None;
        }
        let imm = u32::from_le_bytes(bytes[idx..need].try_into().unwrap());

        return Some(Instruction {
            addr,
            bytes: bytes[..need].to_vec(),
            mnemonic: "mov".into(),
            operands: vec![reg.into(), format!("0x{:x}", imm)],
        });
    }

    // mov r8, imm8  (b0+b reg encoding)
    if (0xB0..=0xB7).contains(&opc) {
        let r_id = (opc & 0x07) as usize;
        let reg = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][r_id];

        if bytes.len() < idx + 1 {
            return None;
        }
        let imm = bytes[idx] as u64;

        return Some(Instruction {
            addr,
            bytes: bytes[..idx + 1].to_vec(),
            mnemonic: "mov".into(),
            operands: vec![reg.into(), format!("0x{:x}", imm)],
        });
    }

    None
}
