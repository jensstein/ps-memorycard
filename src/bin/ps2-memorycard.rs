use ps_memorycard::{auth::read_card_keys, errors::Error, memorycard::PS2MemoryCard, CardResult, get_memory_card, print_specs};

use clap::{Parser, Subcommand};

use std::path::Path;

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

fn cli() -> Result<(), Error> {
    let args = Args::parse();
    let mc = get_and_authenticate_card(&args.keys_directory)?;
    match args.command {
        Commands::Specs => print_specs(&mc)?,
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
