use ps_memorycard::{errors::Error, memorycard::PS2MemoryCard, CardInfo, CardResult, get_memory_card, print_specs};
use ps_memorycard::memorycard::{DirectoryEntryType, MemoryCard};

use clap::{Parser, Subcommand};

use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Directory with MagicGate keys. Should contain iv1.bin, iv2.bin, k1.bin, k2.bin
    #[arg(value_name = "keys-directory")]
    keys_directory: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Prints card info
    Specs,
    /// Dumps the entire card to an image file
    DumpImage {
        /// File to write image to
        #[arg(value_name = "output-file")]
        destination: String
    },
    /// List files in directory on the memory card
    #[command(name = "ls")]
    List {
        /// The memory card path to list
        path: String,
    },
    /// Copy file from memory card (copying to is not supported yet)
    #[command(name = "cp")]
    Copy {
        /// Source file to copy
        #[arg(value_name = "source")]
        src: String,
        /// Destination to write copied data to
        #[arg(value_name = "destination")]
        dst: String,
    }
}

fn get_and_authenticate_card(keys_directory: &str) -> Result<PS2MemoryCard, Error> {
    match get_memory_card(0x054c, 0x02ea, Some(keys_directory))? {
        Some(CardResult::PS1) => {
            return Err("PS1 cards are not supported yet.".into());
        },
        Some(CardResult::PS2(mc)) => {
            Ok(mc)
        },
        None => {
            return Err("No memory card present".into());
        }
    }
}

fn dump_card_image(card: &dyn MemoryCard, info: &CardInfo, destination: &str) -> Result<(), Error> {
    let mut file = File::create(&destination)?;
    println!("Dumping image to {}", destination);
    let pages = info.card_size / info.page_size as u32;
    let bar = indicatif::ProgressBar::new((pages * info.page_size as u32).into());
    let bar_style = match indicatif::ProgressStyle::with_template("[{elapsed}] {bar:40} {bytes:>7}/{total_bytes:7} {msg}") {
        Ok(bar_style) => bar_style,
        Err(error) => return Err(Error::new(format!("Unexpected error when trying to set progress bar style: {}", error)))
    };
    bar.set_style(bar_style);
    for i in 0..pages {
        bar.inc(info.page_size.into());
        let buf = card.read_page(i, info.page_size)?;
        file.write_all(&buf)?;
    }
    bar.finish();
    Ok(())
}

fn list_directory_entries(card: &mut PS2MemoryCard, path: &str) -> Result<(), Error> {
    let entry = card.get_directory_entry_by_path(Path::new(path))?;
    if let Some(entry) = entry {
        if entry.entry_type != DirectoryEntryType::Directory {
            return Err(Error::new(format!("{path} is not a directory.")));
        }
        let directory_entries = card.directory_entries(&entry)?;
        for e in directory_entries {
            println!("{e}");
        }
    } else {
        eprintln!("Cannot access {path}: No such file or directory");
    }
    Ok(())
}

fn copy(card: &mut PS2MemoryCard, src: &str, dst: &str) -> Result<(), Error> {
    let src = Path::new(&src);
    let dst = Path::new(&dst);
    if dst.exists() {
        println!("{} already exists. Proceed? [yn]", dst.display());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input = input.trim().to_lowercase();
        if input != "yes" && input != "y" {
            std::process::exit(0);
        }
    }
    if let Some(entry) = card.get_directory_entry_by_path(src)? {
        let mut file = File::create(dst)?;
        let bar = indicatif::ProgressBar::new(entry.length as u64);
        let bar_style = match indicatif::ProgressStyle::with_template("[{elapsed}] {bar:40} {bytes:>7}/{total_bytes:7} {msg}") {
            Ok(bar_style) => bar_style,
            Err(error) => return Err(Error::new(format!("Unexpected error when trying to set progress bar style: {}", error)))
        };
        bar.set_style(bar_style);
        let mut callback_error = None;
        card.read_file(src, |data| {
            bar.inc(data.len().try_into().expect("Error downcasting length of source file. This should be impossible given the size constraints of memory cards."));
            if let Err(error) = file.write_all(&data) {
                callback_error = Some(error);
            }
        })?;
        bar.finish();
        if let Some(error) = callback_error {
            Err(error.into())
        } else {
            Ok(())
        }
    } else {
        Err(Error::new(format!("Cannot access {}: No such file or directory", src.display())))
    }
}

fn cli() -> Result<(), Error> {
    let args = Args::parse();
    let mut mc = get_and_authenticate_card(&args.keys_directory)?;
    let info = mc.get_card_specs()?;
    match args.command {
        Commands::Specs => print_specs(&mc)?,
        Commands::DumpImage {destination} => {
            dump_card_image(&mc, &info, &destination)?;
        },
        Commands::List {path} => list_directory_entries(&mut mc, &path)?,
        Commands::Copy {src, dst} => copy(&mut mc, &src, &dst)?,
    }
    Ok(())
}

// To use this method in the `or_else` call, its signature must be FnOnce(Error) -> Result
fn exit_with_message(error: Error) -> Result<(), ()> {
    eprintln!("{}", error);
    std::process::exit(1);
}

// https://users.rust-lang.org/t/exiting-gracefully-instead-of-panic/3758
fn main() {
    cli().or_else(exit_with_message).expect("Unexpected error when trying to exit");
}
