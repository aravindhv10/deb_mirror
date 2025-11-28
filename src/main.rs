mod download_dist;
use download_dist::clean_sha;
use download_dist::download_dist;
use download_dist::download_pool;
use download_dist::link_pool;
use download_dist::make_config;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() > 1 {
        if args[1].eq("d") {
            download_dist();
        } else if args[1].eq("p") {
            download_pool();
        } else if args[1].eq("c") {
            clean_sha();
        } else if args[1].eq("l") {
            link_pool();
        } else if args[1].eq("s") {
            make_config();
        }
    } else {
        println!("Run with 1 command line argument...");
        println!("s => generate config files from sources.list");
        println!("d => download dist");
        println!("p => download pool");
        println!("c => clean sha256 directory");
        println!("l => link pool files");
    }
}
