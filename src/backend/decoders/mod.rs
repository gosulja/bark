pub mod amd64;

#[derive(Clone, Debug)]
pub struct Instruction {
    pub addr: u64,             /* Address of the instruction */
    pub bytes: Vec<u8>,        /* Bytes of the instruction */
    pub mnemonic: String,      /* String representation of the instruction */
    pub operands: Vec<String>, /* Operands of the instruction */
}

#[derive(Clone)]
pub struct Var {
    pub name: String,     /* Label/Name of variable */
    pub value: i32,       /* Value of variable */
    pub register: String, /* Register which the variable resides in */
}
