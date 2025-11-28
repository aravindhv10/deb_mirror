use rayon::iter::ParallelBridge;
use rayon::prelude::*;
// use std::collections::HashMap;
// use std::collections::HashSet;
// use std::fs;
use std::fs::File;
use std::io::prelude::*;
// use std::path::Path;
use std::process::Command;
// use std::sync::Mutex;
// use substring::Substring;

fn read_file(name_file: &str) -> Result<String, String> {
    let mut data = String::new();
    match File::open(name_file) {
        Ok(mut file) => match file.read_to_string(&mut data) {
            Ok(_) => {
                return Ok(data);
            }
            Err(e) => {
                println!("Error: {}", e);
                let mut tmp = String::from("Failed to read the file ");
                tmp.push_str(name_file);
                return Err(tmp);
            }
        },
        Err(e) => {
            println!("Error: {}", e);
            let mut tmp = String::from("Failed to open the file ");
            tmp.push_str(name_file);
            return Err(tmp);
        }
    };
}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() > 2 {
        let res = read_file(&args[1]);
        let num_threads: usize = args[2].parse().unwrap();
        match res {
            Ok(o) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(num_threads)
                    .build()
                    .unwrap();
                pool.install(|| {
                    o.split('\n').enumerate().par_bridge().for_each(|x| {
                        let output = Command::new("sh")
                            .arg("-c")
                            .arg(x.1)
                            // .stdout(Stdio::piped())
                            .output();

                        match output {
                            Ok(o) => {
                                let res = String::from_utf8(o.stdout);
                                match res {
                                    Ok(o) => {
                                        o.split('\n').for_each(|x| {
                                            println!("{}", x);
                                        });
                                    }
                                    Err(e) => {
                                        println!("Error reading stdout as string {}", e);
                                    }
                                };
                            }
                            Err(e) => {
                                println!("Error executing command: {}", e);
                            }
                        };
                    });
                });
            }
            Err(e) => {
                println!("Error reading file: {}", e);
            }
        }
    } else {
        println!("Run with 2 command line argument (sh_file, num_threads)...");
    }
}
