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

    /// Integer overflow when computing loaded size
    IntegerOverflowLoaded,
    
    /// Integer overflow when computing current address
    IntegerOverflowCurrentAddress,

    /// Multiple sections overlap where they are loaded
    SectionOverlap,

    /// The ELF didn't supply any segments to load
    NoLoadSegments,
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

/// Load an ELF from disk
///
/// Returns:
///
/// `(entry virtual address, base address for flat map, flat map contents)`
pub fn load_file(path: impl AsRef<Path>) -> Result<(u64, u64, Vec<u8>)> {
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
        let mut _flags = if matches!(bt, Bitness::Bits64) {
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
            _flags = consume!(reader, u32, en, "PH flags")?
        }

        let _align = consume_native!(reader, bt, en, "PH align")?;

        if typ == PT_LOAD {
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

            // Save the address to load to and the bytes
            load.push((vaddr, bytes));
        }
    }

    // Sort load sections by virtual address
    load.sort_by_key(|x| x.0);

    // Get the lowest address loaded 
    let lowest_addr = load.get(0).ok_or(Error::NoLoadSegments)?.0;

    // Flat in-memory loaded representation
    let mut loaded = Vec::new();

    // Load everything!
    let mut cur_addr = lowest_addr;
    for (vaddr, bytes) in load {
        // Get the offset from where we are
        let offset: usize = vaddr.checked_sub(cur_addr)
            .ok_or(Error::SectionOverlap)?
            .try_into()
            .map_err(|_| Error::IntegerTruncationOffset)?;

        // Pad out loaded representation until `vaddr`
        loaded.resize(loaded.len().checked_add(offset)
            .ok_or(Error::IntegerOverflowLoaded)?, 0u8);

        // Place in the bytes
        loaded.extend_from_slice(&bytes);

        // Update current address
        cur_addr = vaddr.checked_add(bytes.len() as u64)
            .ok_or(Error::IntegerOverflowCurrentAddress)?;
    }

    Ok((entry, lowest_addr, loaded))
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        println!("Invalid usage: elfloader <input ELF> <output FELF>");
        return Ok(());
    }

    // Load the ELF
    let (entry, addr, payload) = load_file(&args[1])?;

    // Create the output file
    let mut output = BufWriter::new(File::create(&args[2])
        .map_err(Error::CreateFelf)?);
    output.write_all(b"FELF0001").map_err(Error::WriteFelf)?;
    output.write_all(&entry.to_le_bytes()).map_err(Error::WriteFelf)?;
    output.write_all(&addr.to_le_bytes()).map_err(Error::WriteFelf)?;
    output.write_all(&payload).map_err(Error::WriteFelf)?;
    output.flush().map_err(Error::WriteFelf)?;

    Ok(())
}

