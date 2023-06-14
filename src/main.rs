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

const DIR: &str = "/home/cos/.pman";
mod crypto;

fn retrieve(name: &str, signature: &str) -> io::Result<()> {
    let fp = format!("{}/{}/{}", DIR, &name, &name);
    if !Path::new(&fp).exists() {
        print!("pman: {}\n", format!("Not found").yellow().bold());
        std::process::exit(1);
    }

    let msg = format!("Signature: ").white().bold();
    print!("{}", msg);
    match io::stdout().flush() {
        Ok(()) => (),
        Err(e) => print!("{}\n", e),
    };

    let input = read_password().unwrap();
    if crypto::hash(&input) == signature {
        let mut file = File::open(&fp)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        let decrypted_password = crypto::decrypt(&signature, &buffer);

        let msg = format!("{}", decrypted_password).black().bold();
        print!("Password: {}\n", msg);
    } else {
        let msg = format!("unmatched").yellow().bold();
        print!("\npman: {}\n", msg);
        std::process::exit(1);
    }

    Ok(())
}

fn insert(name: &str, signature: &str) -> io::Result<()> {
    if name == "signature" {
        let msg = format!("Cannot be `signature`").yellow().bold();
        print!("pman: {}\n", msg);
        std::process::exit(1);
    }

    let fp = format!("{}/{}", DIR, &name);
    if Path::new(&fp).is_dir() {
        let msg = format!("Already inserted.").yellow().bold();
        print!("pman: {}\n", msg);
        std::process::exit(1);
    }

    match fs::create_dir(&fp) {
        Ok(()) => (),
        Err(e) => print!("{}\n", e),
    };

    print!("\nPassword: ");
    match io::stdout().flush() {
        Ok(()) => (),
        Err(e) => print!("{}\n", e),
    };

    let file_name = format!("{}/{}/{}", DIR, &name, &name);
    let password = read_password().unwrap();
    let mut file = File::create(&file_name)?;
    file.write_all(crypto::encrypt(&signature, &password).as_bytes())?;

    let msg = format!("Saved!").green().bold();
    println!("pman: {}", msg);

    Ok(())
}

fn delete(name: &str) -> io::Result<()> {
    if name == "signature" {
        let msg = format!("Cannot be `signature`").yellow().bold();
        print!("pman: {}\n", msg);
        std::process::exit(1);
    }

    let fp = format!("{}/{}", DIR, name);
    fs::remove_dir_all(&fp)?;
    let msg = format!("Deleted").red().bold();
    print!("pman: {}\n", msg);

    Ok(())
}

fn list() -> io::Result<()> {
    let entries = fs::read_dir(&DIR)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let dir_name = path.file_name().unwrap().to_str().unwrap();

        if dir_name != "signature" {
            let dir_name = format!("{}", dir_name).white().bold();
            print!("-> {}\n", dir_name);
        }
    }

    Ok(())
}

fn pr_usage() {
    print!("Usage: [action] [user]\n");
}

fn main() -> io::Result<()> {
    let argv: Vec<String> = env::args().collect();

    if argv.len() < 2 {
        pr_usage();
        std::process::exit(1);
    }

    if !Path::new(&DIR).is_dir() {
        fs::create_dir(&DIR)?;
    }

    if !Path::new(&format!("{}/signature", DIR)).is_dir() {
        fs::create_dir(&format!("{}/signature", DIR))?;
    }

    if Path::new(&format!("{}/signature", DIR))
        .read_dir()?
        .next()
        .is_none()
    {
        // get signature
        let msg = "\nRegister Signature: ".white().bold();
        print!("{}", msg);
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };

        let signature = read_password().unwrap();

        // confirm signature
        let msg = "Confirm: ".white().bold();
        print!("{}", msg);
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => print!("{}\n", e),
        };

        let confirm_signature = read_password().unwrap();

        if signature == confirm_signature {
            let mut file = fs::File::create(&format!("{}/signature/signature", DIR))?;
            file.write_all(crypto::hash(&signature.as_str()).as_bytes())?;
        } else {
            let msg = format!("pman: ").yellow().bold();
            print!("{}unmatched.\n", msg);
            std::process::exit(1);
        }
    }

    let mut file = File::open(&format!("{}/signature/signature", DIR))?;
    let mut signature = String::new();
    file.read_to_string(&mut signature)?;

    match argv[1].as_str() {
        "-i" => match insert(&argv[2], &signature) {
            Ok(()) => (),
            Err(_) => pr_usage(),
        },
        "-d" => match delete(&argv[2]) {
            Ok(()) => (),
            Err(_) => pr_usage(),
        },
        "-l" => {
            if argv.len() == 2 {
                match list() {
                    Ok(()) => (),
                    Err(_) => pr_usage(),
                };
            } else {
                match retrieve(&argv[2], &signature) {
                    Ok(()) => (),
                    Err(_) => pr_usage(),
                };
            }
        }
        _ => pr_usage(),
    };

    Ok(())
}
