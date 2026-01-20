mod download_dist;
use download_dist::clean_sha;
use download_dist::download_dist;
use download_dist::download_pool;
use download_dist::link_pool;
use download_dist::make_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() > 1 {
        if args[1].eq("d") {
            return download_dist().await;
        } else if args[1].eq("p") {
            return download_pool().await;
        } else if args[1].eq("c") {
            return clean_sha().await;
        } else if args[1].eq("l") {
            return link_pool().await;
        } else if args[1].eq("s") {
            return make_config().await;
        } else {
            return Err(anyhow::format_err!("Unknown command"));
        }
    } else {
        println!("Run with 1 command line argument...");
        println!("s => generate config files from sources.list");
        println!("d => download dist");
        println!("p => download pool");
        println!("c => clean sha256 directory");
        println!("l => link pool files");
        return Err(anyhow::format_err!("No command given"));
    }
}
