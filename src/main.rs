extern crate rpassword;

use colored::Colorize;
use rpassword::read_password;
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;

mod crypto;

fn insert(name: &str, signature: &str) -> io::Result<()> {
    let fp = format!("pm/{}", &name);
    if Path::new(&fp).is_dir() {
        print!("Aborted: Already inserted!\n");
        std::process::exit(1);
    }

    match fs::create_dir(&fp) {
        Ok(()) => (),
        Err(e) => print!("{}\n", e),
    };

    print!("Password: ");
    match io::stdout().flush() {
        Ok(()) => (),
        Err(e) => print!("{}\n", e),
    };

    let file_name = format!("pm/{}/{}", &name, &name);
    let password = read_password().unwrap();
    let mut file = File::create(&file_name)?;
    file.write_all(crypto::encrypt(&signature, &password).as_bytes())?;

    let msg = format!("Saved!").green().bold();
    println!("{}", msg);

    Ok(())
}

fn pr_usage() {
    print!("Usage: <flag> <user>\n");
}

fn main() -> io::Result<()> {
    let argv: Vec<String> = env::args().collect();

    if argv.len() != 3 {
        pr_usage();
        std::process::exit(1);
    }

    if !Path::new("pm").is_dir() {
        match fs::create_dir("pm") {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };
    }

    if !Path::new("pm/signature").is_dir() {
        match fs::create_dir("pm/signature") {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };
    }

    if Path::new("pm/signature").read_dir()?.next().is_none() {
        // get signature
        let msg = "Register Signature: ".white().bold();
        print!("{}", msg);
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };

        let signature = read_password().unwrap();

        // confirm signature
        let msg = "Confirm Signature: ".white().bold();
        print!("{}", msg);
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };

        let confirm_signature = read_password().unwrap();

        if signature == confirm_signature {
            let mut file = fs::File::create("pm/signature/signature")?;
            file.write_all(crypto::hash(&signature.as_str()).as_bytes())?;
        }
    }

    let mut file = File::open("pm/signature/signature")?;
    let mut signature = String::new();
    file.read_to_string(&mut signature)?;

    match argv[1].as_str() {
        "-i" => match insert(&argv[2], &signature) {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        },
        _ => pr_usage(),
    };

    Ok(())
}
