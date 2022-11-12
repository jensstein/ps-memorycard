use ps_memorycard::{auth::read_card_keys, errors::Error, memorycard::PS2MemoryCard, CardInfo, CardResult, get_memory_card, print_specs};
use ps_memorycard::memorycard::MemoryCard;

use clap::{Parser, Subcommand};

use std::path::Path;
use std::fs::File;
use std::io::Write;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(value_name = "keys-directory")]
    keys_directory: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Specs,
    // Command for dumping the entire card to an image file
    DumpImg {
        #[arg(value_name = "output-file")]
        destination: String
    },
}

fn get_and_authenticate_card(keys_directory: &str) -> Result<PS2MemoryCard, Error> {
    match get_memory_card(0x054c, 0x02ea)? {
        Some(CardResult::PS1) => {
            return Err("PS1 cards are not supported yet.".into());
        },
        Some(CardResult::PS2(mc)) => {
            if !mc.is_authenticated()? {
                let card_keys = read_card_keys(Path::new(keys_directory))?;
                match mc.authenticate(&card_keys) {
                    Ok(_) => {
                        mc.validate()?;
                        mc.set_termination_code()?;
                    },
                    Err(error) => {
                        return Err(format!("Error authenticating card: {}", error).into());
                    }
                }
            }
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

fn cli() -> Result<(), Error> {
    let args = Args::parse();
    let mc = get_and_authenticate_card(&args.keys_directory)?;
    let info = mc.get_card_specs()?;
    match args.command {
        Commands::Specs => print_specs(&mc)?,
        Commands::DumpImg {destination} => {
            dump_card_image(&mc, &info, &destination)?;
        },
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
