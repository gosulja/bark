# bark
A mini disassembler & decompiler for amd64.

# usage
Edit `input.s` with a set of bytes (machine code).
For example, `mov rax, 0x2` is already set as an example:
```
48C7C002000000
```

Run
```
cargo run
```
