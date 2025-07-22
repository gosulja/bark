use super::Instruction;

pub fn decode(bytes: &[u8], addr: u64) -> Option<Instruction> {
    /*
        References: https://wiki.osdev.org/X86-64_Instruction_Encoding
    */

    /* The type of instruction resides at bytes[0] */
    match bytes[0] {
        /*
            mov immediate to 32 bit reg (eax - edi)
            these 32 bit registers reside in this range when encoded.
        */
        0xB8..=0xBF => {
            /*
                If it's shorter than 5, it's invalid because
                we expect one byte for the opcode, and four bytes for the imm value
            */
            if bytes.len() < 5 {
                return None;
            }

            /* Register index */
            let ridx = bytes[0] - 0xB8;
            /* Map the 32 bit registers */
            let rname = match ridx {
                0 => "eax",
                1 => "ecx",
                2 => "edx",
                3 => "ebx",
                4 => "esp",
                5 => "ebp",
                6 => "esi",
                7 => "edi",
                _ => "?",
            };

            /* Convert next 4 bytes of the immediate value into an i32 data type value */
            let imm = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);

            /* Return the instruction e.g mov eax, 0x2 */
            Some(Instruction {
                addr,
                bytes: bytes[0..5].to_vec(),
                mnemonic: "mov".to_string(),
                operands: vec![rname.to_string(), format!("0x{:x}", imm)],
            })
        }

        /*
            rex prefix + mov for 64 bit
            The first byte is the rex prefix
        */
        0x48 => {
            /* We need more than 2 bytes */
            if bytes.len() < 2 {
                return None;
            }

            /* This time, bytes[1] is the instruction as we have a rex prefix we need to skip */
            match bytes[1] {
                /*
                    mov immediate to 64 bit reg (rax - rdi)
                    these 64 bit registers reside in this range when encoded.
                */
                0xB8..=0xBF => {
                    /*
                        If it's shorter than 5, it's invalid because
                        we expect one byte for the prefix '0x48',
                        one byte for the range of 0xb8 -> 0xbf,
                        and then four bytes for the imm value
                    */
                    if bytes.len() < 6 {
                        return None;
                    }

                    /* since bytes[0] is the prefix, we need to index the instruction which is at bytes[1] */
                    let ridx = bytes[1] - 0xB8;

                    /*
                        Map the 64 bit registers
                    */
                    let rname = match ridx {
                        0 => "rax",
                        1 => "rcx",
                        2 => "rdx",
                        3 => "rbx",
                        4 => "rsp",
                        5 => "rbp",
                        6 => "rsi",
                        7 => "rdi",
                        _ => "?",
                    };

                    /* Convert next 4 bytes of the immediate value into an i32 data type value */
                    let imm = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);

                    Some(Instruction {
                        addr,
                        bytes: bytes[0..5].to_vec(),
                        mnemonic: "mov".to_string(),
                        operands: vec![rname.to_string(), format!("0x{:x}", imm)],
                    })
                }

                /*
                    mov to reg, 64 bit.
                */
                0xC7 => {
                    /*
                        We need to ensure we're decoding the correct
                        instruction format.

                        basically do like we've done before, check the length of the bytes.
                        However since bytes[1] is 0xc7, which corresponds to a mov instruction which utilisez the 0xc7 opcode,
                        we need to ensure that bytes[2] does not meet the condition of 0xc0.
                        this will
                    */
                    if bytes.len() < 7 || (bytes[2] & 0xC0) != 0xC0 {
                        return None;
                    }

                    let ridx = bytes[2] & 0x07;
                    let rname = match ridx {
                        0 => "rax",
                        1 => "rcx",
                        2 => "rdx",
                        3 => "rbx",
                        4 => "rsp",
                        5 => "rbp",
                        6 => "rsi",
                        7 => "rdi",
                        _ => "?",
                    };
                    let imm = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                    Some(Instruction {
                        addr,
                        bytes: bytes[0..7].to_vec(),
                        mnemonic: "mov".to_string(),
                        operands: vec![rname.to_string(), format!("0x{:x}", imm)],
                    })
                }

                _ => None,
            }
        }

        _ => None,
    }
}
