use std::process::Command;

fn mysync(mut args: Vec<String>) {
    args[0] = String::from("--progress");
    args.push(String::from("-avh"));

    Command::new("rsync")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    Command::new("sync").spawn().unwrap().wait().unwrap();

    Command::new("sync").spawn().unwrap().wait().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    mysync(args);
}
