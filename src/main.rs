use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, BufWriter, Write};
use std::mem::size_of;
use std::path::Path;

/// Friendly wrapper around [`Error`]
type Result<T> = std::result::Result<T, Error>;

/// Error types
#[derive(Debug)]
pub enum Error {
    /// Failed to open the ELF file
    Open(std::io::Error),

    /// Failed to consume a field from the input
    Consume(&'static str, std::io::Error),

    /// ELF magic was missing from file
    MissingMagic,

    /// ELF indiciated a bitness which was not a valid variant
    InvalidBitness(u8),

    /// ELF indiciated an endianness which was not a valid variant
    InvalidEndianness(u8),

    /// ELF version was unknown
    UnknownVersion(u8),

    /// Expected an executable but got a different ELF type
    ExpectedExecutable(u16),

    /// Seeking to the program headers failed
    SeekProgramHeaders(std::io::Error),

    /// Seeking the initialized data for a loaded segment failed
    LoadSeek(std::io::Error),

    /// Reading initialized bytes from file failed
    ReadInit(std::io::Error),

    /// Creating the FELF failed
    CreateFelf(std::io::Error),

    /// Writing the FELF failed
    WriteFelf(std::io::Error),

    /// Truncated integer for filesz
    IntegerTruncationFileSz,

    /// Truncated integer for memsz
    IntegerTruncationMemSz,

    /// Trucated integer for offset
    IntegerTruncationOffset,

    /// Integer overflow when computing current address
    IntegerOverflowCurrentAddress,

    /// Multiple sections overlap where they are loaded
    SectionOverlap,

    /// The ELF didn't supply any segments to load
    NoLoadSegments,

    /// The `--base` provided did not parse into a `u64` correctly
    InvalidBase(std::num::ParseIntError),
}

/// Consume bytes from a reader
macro_rules! consume {
    // Consume a `u8`
    ($reader:expr, $field:expr) => {{
        // Create buffer
        let mut tmp = [0u8; 1];
        $reader.read_exact(&mut tmp).map(|_| {
            tmp[0]
        }).map_err(|x| Error::Consume($field, x))
    }};

    ($reader:expr, $ty:ty, $endian:expr, $field:expr) => {{
        // Create buffer for type
        let mut tmp = [0u8; size_of::<$ty>()];

        match $endian {
            Endianness::Little => {
                // Read the bytes and convert
                $reader.read_exact(&mut tmp).map(|_| {
                    <$ty>::from_le_bytes(tmp)
                }).map_err(|x| Error::Consume($field, x))
            }
            Endianness::Big => {
                // Read the bytes and convert
                $reader.read_exact(&mut tmp).map(|_| {
                    <$ty>::from_be_bytes(tmp)
                }).map_err(|x| Error::Consume($field, x))
            }
        }
    }};

    ($reader:expr, $size:expr, $field:expr) => {{
        // Create buffer for type
        let mut tmp = [0u8; $size];

        // Read the bytes and convert
        $reader.read_exact(&mut tmp).map(|_| {
            tmp
        }).map_err(|x| Error::Consume($field, x))
    }};
}

macro_rules! consume_native {
    ($reader:expr, $bitness:ident, $endian:expr, $field:expr) => {{
        match $bitness {
            Bitness::Bits32 => {
                consume!($reader, u32, $endian, $field).map(|x| x as u64)
            },
            Bitness::Bits64 => consume!($reader, u64, $endian, $field),
        }
    }};
}

/// Bitnesses for ELF files
#[derive(Debug)]
enum Bitness {
    /// 32-bit ELF
    Bits32,

    /// 64-bit ELF
    Bits64,
}

impl TryFrom<u8> for Bitness {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        Ok(match val {
            1 => Bitness::Bits32,
            2 => Bitness::Bits64,
            _ => return Err(Error::InvalidBitness(val)),
        })
    }
}

/// Endianness for ELF files
#[derive(Debug)]
enum Endianness {
    /// Little endian
    Little,

    /// Big endian
    Big,
}

impl TryFrom<u8> for Endianness {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        Ok(match val {
            1 => Endianness::Little,
            2 => Endianness::Big,
            _ => return Err(Error::InvalidEndianness(val)),
        })
    }
}

/// Loaded segment
const PT_LOAD: u32 = 1;

/// Executable segment
const PF_X: u32 = 1 << 0;

/// Writable segment
const PF_W: u32 = 1 << 1;

/// Readable segment
const PF_R: u32 = 1 << 2;

/// Load an ELF from disk
///
/// Returns:
///
/// `(entry virtual address, base address for flat map, flat map contents)`
pub fn write_file(path: impl AsRef<Path>, base: Option<u64>,
        mut output: impl Write, binary: bool, save_perms: bool) -> Result<()> {
    // Open the file
    let mut reader =
        BufReader::new(File::open(path).map_err(Error::Open)?);

    // Check that this is an ELF
    if &consume!(reader, 4, "ELF magic")? != b"\x7fELF" {
        return Err(Error::MissingMagic);
    }

    // Get the bitness and endianness
    let bt = Bitness::try_from(consume!(reader, "bitness")?)?;
    let en = Endianness::try_from(consume!(reader, "endianness")?)?;

    // Make sure the ELF version matches
    let version = consume!(reader, "version")?;
    if version != 1 {
        return Err(Error::UnknownVersion(version));
    }

    // We don't care about the ABI
    let _abi    = consume!(reader, "abi")?;
    let _abiver = consume!(reader, "abi version")?;
    let _pad    = consume!(reader, 7, "padding")?;

    let _objtyp  = consume!(reader, u16, en, "type")?;
    let _machine = consume!(reader, u16, en, "machine")?;
    let _elfver  = consume!(reader, u32, en, "ELF version")?;

    let entry = consume_native!(reader, bt, en, "entry point")?;

    let phoff  = consume_native!(reader, bt, en, "program header offset")?;
    let _shoff = consume_native!(reader, bt, en, "section header offset")?;

    let _flags  = consume!(reader, u32, en, "flags")?;
    let _ehsize = consume!(reader, u16, en, "ELF header size")?;
    let _phesz  = consume!(reader, u16, en, "program header entry size")?;
    let phcnt   = consume!(reader, u16, en, "program header entries")?;

    // Seek to the program headers
    reader.seek(SeekFrom::Start(phoff))
        .map_err(Error::SeekProgramHeaders)?;

    // List of sections to load
    let mut load = Vec::new();

    // Go through each program header entry
    for _ in 0..phcnt {
        // Get header type
        let typ = consume!(reader, u32, en, "PH type")?;

        // 64-bit has flags here
        let mut flags = if matches!(bt, Bitness::Bits64) {
            consume!(reader, u32, en, "PH flags")?
        } else { 0 };

        // Parse program header
        let offset = consume_native!(reader, bt, en, "PH offset")?;
        let vaddr  = consume_native!(reader, bt, en, "PH vaddr")?;
        let _paddr = consume_native!(reader, bt, en, "PH paddr")?;
        let filesz = consume_native!(reader, bt, en, "PH filesz")?;
        let memsz  = consume_native!(reader, bt, en, "PH memsz")?;

        // 32-bit has flags here
        if matches!(bt, Bitness::Bits32) {
            flags = consume!(reader, u32, en, "PH flags")?
        }

        let _align = consume_native!(reader, bt, en, "PH align")?;

        if typ == PT_LOAD {
            // If the section is zero size, skip it entirely
            if memsz == 0 {
                continue;
            }

            // Read initialized bytes from file if needed
            let mut bytes = Vec::new();
            if filesz > 0 {
                // Save the current position
                let stream_pos = reader.stream_position()
                    .map_err(Error::LoadSeek)?;

                // Seek to the bytes in the file
                reader.seek(SeekFrom::Start(offset))
                    .map_err(Error::LoadSeek)?;

                // Resize buffer
                bytes.resize(filesz.try_into()
                    .map_err(|_| Error::IntegerTruncationFileSz)?, 0u8);

                // Read initialized bytes from file
                reader.read_exact(&mut bytes).map_err(Error::ReadInit)?;

                // Seek back to where we were
                reader.seek(SeekFrom::Start(stream_pos))
                    .map_err(Error::LoadSeek)?;
            }

            // Pad out with zeros until memory size
            bytes.resize(memsz.try_into()
                .map_err(|_| Error::IntegerTruncationMemSz)?, 0u8);

            // Determine permissions for this segment
            let r = (flags & PF_R) != 0;
            let w = (flags & PF_W) != 0;
            let x = (flags & PF_X) != 0;

            // Save the address to load to and the bytes
            load.push((vaddr, bytes, r, w, x));
        }
    }

    // Sort load sections by virtual address
    load.sort_by_key(|x| x.0);

    // Start load at the specified `base`, otherwise use the lowest address of
    // all the LOAD sections
    let lowest_addr = base.unwrap_or(
        load.get(0).ok_or(Error::NoLoadSegments)?.0);

    if !binary {
        // Write the FELF header
        if !save_perms {
            output.write_all(b"FELF0001").map_err(Error::WriteFelf)?;
        } else {
            output.write_all(b"FELF0002").map_err(Error::WriteFelf)?;
        }

        output
            .write_all(&entry.to_le_bytes())
            .map_err(Error::WriteFelf)?;
        output
            .write_all(&lowest_addr.to_le_bytes())
            .map_err(Error::WriteFelf)?;
    }

    // Permissions vector
    let mut perms = Vec::new();

    // Write everything!
    let mut cur_addr = lowest_addr;
    for (vaddr, bytes, r, w, x) in load {
        // Get the offset from where we are
        let offset: usize = vaddr.checked_sub(cur_addr)
            .ok_or(Error::SectionOverlap)?
            .try_into()
            .map_err(|_| Error::IntegerTruncationOffset)?;

        // Pad out loaded representation until `vaddr`
        const ZERO_BUF: [u8; 1024 * 8] = [0u8; 1024 * 8];

        let mut padding = offset;
        while padding > ZERO_BUF.len() {
            output.write_all(&ZERO_BUF).map_err(Error::WriteFelf)?;
            if save_perms {
                perms.write_all(&ZERO_BUF).map_err(Error::WriteFelf)?;
            }
            padding -= ZERO_BUF.len();
        }
        output.write_all(&ZERO_BUF[..padding])
            .map_err(Error::WriteFelf)?;
        if save_perms {
            perms.write_all(&ZERO_BUF[..padding])
                .map_err(Error::WriteFelf)?;
        }

        // Place in the bytes
        output.write_all(&bytes).map_err(Error::WriteFelf)?;

        if save_perms {
            // Place in all the permission bytes
            let perm_flags =
                if r { PF_R } else { 0 } |
                if w { PF_W } else { 0 } |
                if x { PF_X } else { 0 };
            perms.resize(perms.len() + bytes.len(), perm_flags as u8);
        }

        // Update current address
        cur_addr = vaddr
            .checked_add(bytes.len() as u64)
            .ok_or(Error::IntegerOverflowCurrentAddress)?;
    }

    if save_perms {
        // Add permissions to file
        output.write_all(&perms).map_err(Error::WriteFelf)?;
    }

    output.flush().map_err(Error::WriteFelf)?;

    Ok(())
}

/// Entry point
fn main() -> Result<()> {
    // Get the command line arguments
    let mut args = std::env::args().collect::<Vec<_>>();

    // Check if the `--binary` flag was specified
    let mut binary = false;
    args.retain(|x| if x == "--binary" { binary = true; false } else { true });

    // Check if the `--perms` flag was specified
    let mut perms = false;
    args.retain(|x| if x == "--perms" { perms = true; false } else { true });

    // Perms flag overrides the binary flag
    if perms {
        binary = false;
    }

    // Check if the `--base=` flag was specified
    let mut base = None;
    args.retain(|x| {
        if x.starts_with("--base=") {
            // Default to hex, skip over `--base=`
            let mut radix = 16;
            let mut x     = &x[7..];

            if x.starts_with("0x") {
                radix = 16;
                x = &x[2..];
            } else if x.starts_with("0o") {
                radix = 8;
                x = &x[2..];
            } else if x.starts_with("0b") {
                radix = 2;
                x = &x[2..];
            } else if x.starts_with("0d") {
                radix = 10;
                x = &x[2..];
            }

            // Convert to a `u64`
            base = Some(u64::from_str_radix(x, radix)
                .map_err(Error::InvalidBase));

            // Don't keep this argument
            false
        } else { true }
    });

    // Can't use `?` in closure
    let base = if let Some(base) = base {
        Some(base?)
    } else { None };

    if args.len() != 3 {
        println!(
r#"Usage: elfloader [--perms] [--binary] [--base=<addr>] <input ELF> <output>
    --binary      - Don't output a FELF, output the raw loaded image with no
                    metadata
    --perms       - Create a FELF0002 which includes permission data, overrides
                    --binary
    --base=<addr> - Force the output to start at `<addr>`, zero padding from
                    the base to the start of the first LOAD segment if needed.
                    `<addr>` is default hex, can be overrided with `0d`, `0b`,
                    `0x`, or `0o` prefixes.
                    Warning: This does not _relocate_ to base, it simply starts
                    the output at `<addr>` (adding zero bytes such that the
                    output image can be loaded at `<addr>` instead of the
                    original ELF base)
    <input ELF>   - Path to input ELF
    <output>      - Path to output file"#);
        return Ok(());
    }

    // Create the output file
    let mut output = BufWriter::new(File::create(&args[2])
        .map_err(Error::CreateFelf)?);
    write_file(&args[1], base, &mut output, binary, perms)?;

    Ok(())
}

