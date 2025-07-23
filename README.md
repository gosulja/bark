# bark
A mini disassembler & decompiler for amd64.

<img width="875" height="264" alt="image" src="https://github.com/user-attachments/assets/b27bf352-cb03-45e0-9a85-74961b41c411" />


Refer to https://github.com/longbridge/gpui-component for use on components.

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
