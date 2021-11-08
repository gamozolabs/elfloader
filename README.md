# Summary

`elfloader` is a super simple loader for ELF files that generates a flat
in-memory representation of the ELF.

It simply concatenates all `LOAD` sections together, using zero-padding if
there are gaps, into one big flat file.

This file includes zero-initialization of `.bss` sections, and thus can be used
directly as a shellcode payload.

If you don't want to waste time with fail-open linker scripts, this is probably
a great way to go.

This doesn't handle any relocations, it's on you to make sure the original ELF
is based at the address you want it to be at.

# Usage

To use this tool, simply:

```
Usage: elfloader [--binary] [--base=<addr>] <input ELF> <output>
    --binary      - Don't output a FELF, output the raw loaded image with no
                    metadata
    --base <addr> - Force the output to start at <addr>, zero padding from the
                    base to the start of the first LOAD segment if needed.
                    <addr> is default hex, can be overrided with `0d`, `0b`,
                    `0x`, or `0o` prefixes.
                    Warning: This does not _relocate_ to base, it simply starts
                    the output at `<addr>` (adding zero bytes such that the
                    output image can be loaded at `<addr>` instead of the
                    original ELF base)
    <input ELF>   - Path to input ELF
    <output>      - Path to output file
```

To install this tool run:

`cargo install --path .`

Now you can use `elfloader` from anywhere in your shell!

# Example

There's an example in `example_small_program`, simply run `make` or `nmake`
and this should generate an `example.bin` which is 8 bytes.

```
pleb@gamey ~/elfloader/example_small_program $ make
cargo build --release
    Finished release [optimized] target(s) in 0.03s
elfloader --binary target/aarch64-unknown-none/release/example_small_program example.bin
pleb@gamey ~/elfloader/example_small_program $ ls -l ./example.bin 
-rw-r--r-- 1 pleb pleb 8 Nov  8 12:27 ./example.bin

pleb@gamey ~/elfloader/example_small_program $ objdump -d target/aarch64-unknown-none/release/example_small_program

target/aarch64-unknown-none/release/example_small_program:     file format elf64-littleaarch64


Disassembly of section .text:

00000000133700b0 <_start>:
    133700b0:   8b000020        add     x0, x1, x0
    133700b4:   d65f03c0        ret
```

Now you can write your shellcode in Rust, and you don't have to worry about
whether you emit `.data`, `.rodata`, `.bss`, etc. This will handle it all for
you!

# Iternals

This tool doesn't care about anything except for `LOAD` sections. It determines
the endianness (little vs big) and bitness (32 vs 64) from the ELF header,
and from there it creates a flat image based on program header virtual
addresses (where it's loaded), file size (number of initialized bytes) and
mem size (size of actual memory region). The bytes are initialized from the
file based on the offset and file size, and this is then extended with zeros
until mem size (or truncated if mem size is smaller than file size).

These `LOAD` sections are then concatenated together with zero-byte padding
for gaps.

This is designed to be incredibly simple, and agnostic to the ELF input. It
could be an executable, object file, shared object, core dump, etc, doesn't
really care. It'll simply give you the flat representation of the memory,
nothing more.

This allows you to turn any ELF into shellcode, or a simpler file format that
is easier to load in hard-to-reach areas, like embedded devices. Personally,
I developed this for my MIPS NT 4.0 loader which allows me to run Rust code.

# FELF0001 format

This tool by default generates a FELF file format. This is a Falk ELF. This
is a simple file format:

```
FELF0001 - Magic header
entry    - 64-bit little endian integer of the entry point address
base     - 64-bit little endian integer of the base address to load the image
<image>  - Rest of the file is the raw image, to be loaded at `base` and jumped
           into at `entry`
```

