extern crate reqwest;
extern crate substring;

use anyhow::Context;
use futures::StreamExt;
use sha2::Digest;
use std::cmp::min;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::process::ExitStatus;
use std::sync::Mutex;
use substring::Substring;
use tokio::io::AsyncReadExt;

const TEXT_PACKAGE: &str = "Package: ";
const TEXT_VERSION: &str = "Version: ";
const TEXT_FILENAME: &str = "Filename: ";
const TEXT_SHA256: &str = "SHA256: ";

const TEXT_DEB: &str = "deb";
const TEXT_HTTP: &str = "http://";
const TEXT_HTTPS: &str = "https://";

const STORE: &str = "SHA256";
const TMP: &str = "TMP";
const WASTE: &str = "WASTE";

async fn sha256_digest(dest: &str) -> anyhow::Result<String> {
    let data = tokio::fs::read(&dest).await?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let ret = hex::encode(result);
    Ok(ret)
}

fn map_num_url_to_num_threads(num_url: u16) -> u16 {
    match num_url {
        0 => {
            return 1;
        }
        1 => {
            return 4;
        }
        _ => {
            return 8;
        }
    }
}

async fn read_list_url_mirrors() -> anyhow::Result<String> {
    tokio::fs::read_to_string("list.url_mirrors.txt")
        .await
        .with_context(|| format!("failed to read list.url_mirrors.txt"))
}

async fn read_list_dist_packages() -> anyhow::Result<String> {
    tokio::fs::read_to_string("list.dist_packages.txt")
        .await
        .with_context(|| format!("failed to read list.dist_packages.txt"))
}

async fn download_wget(url: &str, file_name: &str) -> anyhow::Result<()> {
    let res = tokio::process::Command::new("wget")
        .arg("-c")
        .arg(url)
        .arg("-O")
        .arg(file_name)
        .status()
        .await?;

    match res.code() {
        Some(c) => {
            if c == 0 {
                Ok(())
            } else {
                Err(anyhow::format_err!(
                    "Failed to download file {} from url {}. Wget had exit status {}",
                    file_name,
                    url,
                    c
                ))
            }
        }
        None => Err(anyhow::format_err!(
            "Failed to download file {} from url {}. Wget terminated",
            file_name,
            url,
        )),
    }
}

async fn download_aria(url: &str, file_name: &str) -> anyhow::Result<()> {
    let res = tokio::process::Command::new("aria2c")
        .arg("-c")
        .arg("-x4")
        .arg("-j4")
        .arg(url)
        .arg("-o")
        .arg(file_name)
        .status()
        .await?;

    match res.code() {
        Some(c) => {
            if c == 0 {
                Ok(())
            } else {
                Err(anyhow::format_err!(
                    "Failed to download file {} from url {}. Wget had exit status {}",
                    file_name,
                    url,
                    c
                ))
            }
        }
        None => Err(anyhow::format_err!(
            "Failed to download file {} from url {}. Wget terminated",
            file_name,
            url,
        )),
    }
}

async fn download_reqwest(url: &str, file_name: impl AsRef<Path>) -> anyhow::Result<()> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("Failed to send request to URL: {}", url))?;

    let response = response
        .error_for_status()
        .with_context(|| format!("Server returned an error for {}", url))?;

    let path = file_name.as_ref();
    let mut dest = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("Failed to create file at {:?}", path))?;

    let content = response
        .bytes()
        .await
        .context("Failed to read response bytes")?;

    let mut content_cursor = std::io::Cursor::new(content);
    tokio::io::copy(&mut content_cursor, &mut dest)
        .await
        .with_context(|| format!("Failed to write data to {:?}", path))?;

    Ok(())
}

async fn download(url: &str, file_name: &str) -> anyhow::Result<()> {
    download_aria(url, file_name).await
}

async fn mkdir(loc: &str) -> anyhow::Result<()> {
    match std::path::Path::new(loc).parent() {
        Some(parent_dir) => tokio::fs::create_dir_all(parent_dir)
            .await
            .with_context(|| format!("Failed to create directory {:?}", parent_dir)),
        None => Err(anyhow::format_err!(
            "invalid location {}, could not create directory.",
            loc
        )),
    }
}

async fn do_link(sha: &str, loc: &str) -> anyhow::Result<()> {
    match std::path::Path::new(loc).parent() {
        Some(parent_dir) => {
            match tokio::fs::create_dir_all(parent_dir).await {
                Ok(o) => {}
                Err(e) => {}
            };
        }
        None => {}
    };

    let mut counts: i16 = 0;
    loc.split('/').for_each(|x| {
        if x.eq("..") {
            counts -= 1;
        } else if !x.eq(".") {
            counts += 1;
        }
    });
    let mut dest = String::new();
    for _ in 0..(counts - 1) {
        dest.push_str("../");
    }
    dest.push_str("SHA256/");
    dest.push_str(sha);

    tokio::fs::symlink(/*original = */ &dest, /*link = */ &loc)
        .await
        .with_context(|| format!("Failed creating symlink from {} to {}", loc, dest))
}

#[derive(Debug)]
struct package_pair {
    sha256: String,
    filename: String,
}

type package_pair_list = Vec<package_pair>;

async fn read_packages() -> anyhow::Result<package_pair_list> {
    let files_1 = read_list_dist_packages().await?;
    println!("{:?}", files_1);

    fn match_begin(in_str: &str, pattern: &str) -> bool {
        if in_str.len() > pattern.len() {
            return in_str[0..pattern.len()].eq(pattern);
        } else {
            return false;
        }
    }

    fn has_dbgsym(instr: &str) -> bool {
        match instr.find("-dbgsym_") {
            Some(_) => {
                return true;
            }
            None => {
                return false;
            }
        }
    }

    fn has_dbg(instr: &str) -> bool {
        match instr.find("-dbg_") {
            Some(_) => {
                return true;
            }
            None => {
                return false;
            }
        }
    }

    fn has_packages(instr: &str) -> bool {
        const TEXT_PACKAGES: &str = "Packages";
        if instr.len() >= TEXT_PACKAGES.len() {
            let ret = instr[instr.len() - TEXT_PACKAGES.len()..].eq(TEXT_PACKAGES);
            return ret;
        } else {
            return false;
        }
    }

    let mut files_2: String = String::new();

    for x in files_1.split('\n').filter(|x| has_packages(x)) {
        println!("Got package {}", x);
        let package_file_contents = tokio::fs::read_to_string(x)
            .await
            .with_context(|| format!("failed to read the Packages file {}", x))?;
        files_2.push_str(package_file_contents.as_str());
        files_2.push('\n');
    }

    if files_2.len() == 0 {
        return Err(anyhow::format_err!("Failed to read any packages"));
    }

    let mut meta_data = package_pair_list::new();

    let mut filename: String = String::new();
    let mut sha256: String = String::new();
    let mut version: String = String::new();

    enum LoopState {
        NeedPackage = 0,
        NeedVersion = 1,
        NeedFilename = 2,
        NeedSha256 = 3,
    }

    let mut current_state: LoopState = LoopState::NeedPackage;
    files_2.split('\n').for_each(|x| {
        match current_state {
            LoopState::NeedPackage => {
                if match_begin(x, TEXT_PACKAGE) {
                    current_state = LoopState::NeedVersion;
                }
            }
            LoopState::NeedVersion => {
                if match_begin(x, TEXT_VERSION) {
                    version = String::from(x.substring(TEXT_VERSION.len(), x.len()));
                    current_state = LoopState::NeedFilename;
                }
            }
            LoopState::NeedFilename => {
                if match_begin(x, TEXT_FILENAME) {
                    filename = String::from(x.substring(TEXT_FILENAME.len(), x.len()));
                    if (has_dbg(&filename)) || (has_dbgsym(&filename)) {
                        current_state = LoopState::NeedPackage;
                    } else {
                        current_state = LoopState::NeedSha256;
                    }
                }
            }
            LoopState::NeedSha256 => {
                if match_begin(x, TEXT_SHA256) {
                    sha256 = String::from(x.substring(TEXT_SHA256.len(), x.len()));
                    current_state = LoopState::NeedPackage;
                    meta_data.push(package_pair {
                        sha256: sha256.clone(),
                        filename: filename.clone(),
                    });
                }
            }
        };
    });

    return Ok(meta_data);
}

async fn link_pool_in_dist(file_name: &str) {
    let loc: Vec<&str> = file_name.split('/').collect();
    let mut out = String::new();
    for i in 0..loc.len() - 1 {
        if !loc[i].eq(".") {
            out.push_str(loc[i]);
            out.push('/');
            let mut dest: String = out.clone();
            dest.push_str("pool");
            let _res = tokio::fs::symlink(/*original = */ "../pool", /*link = */ &dest).await;
        }
    }
}

async fn link_pool_package(
    x: std::sync::Arc<package_pair_list>,
    j: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    const batch_size: u64 = 16 as u64;
    loop {
        let begin = j.fetch_add(batch_size, std::sync::atomic::Ordering::Relaxed) as usize;
        if begin < x.len() {
            let end = std::cmp::min(begin + batch_size as usize, x.len());
            for idx in begin..end {
                let item = &x[idx];
                let _res = do_link(item.sha256.as_str(), item.filename.as_str()).await;
            }
        } else {
            break;
        }
    }
}

pub async fn link_pool() -> anyhow::Result<()> {
    async fn slave(x: &str) -> anyhow::Result<()> {
        mkdir(x).await?;
        link_pool_in_dist(x).await;
        Ok(())
    }

    const num_threads: usize = 16;

    let files = read_list_dist_packages().await?;

    futures::stream::iter(files.split('\n').filter(|x| x.len() > 0).map(|x| slave(x)))
        .buffer_unordered(num_threads)
        .collect::<Vec<_>>()
        .await;

    let meta_data = std::sync::Arc::new(read_packages().await?);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let data_ref = std::sync::Arc::clone(&meta_data);
        let index_ref = std::sync::Arc::clone(&counter);
        handles.push(link_pool_package(data_ref, index_ref));
    }

    futures::future::join_all(handles).await;

    Ok(())
}

async fn move_file_from_waste_to_sha256(sha256: &str) -> anyhow::Result<()> {
    let mut src = String::from(WASTE);
    src.push('/');
    src.push_str(sha256);

    let mut dst = String::from(STORE);
    dst.push('/');
    dst.push_str(sha256);

    tokio::fs::rename(src.as_str(), dst.as_str())
        .await
        .with_context(|| {
            format!(
                "Failed to link the file {} to {}",
                src.as_str(),
                dst.as_str()
            )
        })
}

async fn move_file_from_waste_to_sha256_list(
    x: std::sync::Arc<Vec<String>>,
    y: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    const b: u64 = 16 as u64;
    loop {
        let begin = y.fetch_add(b, std::sync::atomic::Ordering::Relaxed) as usize;
        if begin < x.len() {
            let end = std::cmp::min(begin + b as usize, x.len());
            for i in begin..end {
                let item = &x[i];
                match move_file_from_waste_to_sha256(item.as_str()).await {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Failed to find the file {} while cleaning", item);
                    }
                }
            }
        } else {
            break;
        }
    }
}

pub async fn clean_sha() -> anyhow::Result<()> {
    let packages = read_packages().await?;
    let shas: Vec<String> = packages.into_iter().map(|x| x.sha256).collect();
    let shas_ref = std::sync::Arc::new(shas);

    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    const num_threads: u16 = 16;
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let data_ref = std::sync::Arc::clone(&shas_ref);
        let index_ref = std::sync::Arc::clone(&counter);
        let tmp = move_file_from_waste_to_sha256_list(data_ref, index_ref);
        handles.push(tmp);
    }

    futures::future::join_all(handles).await;

    Ok(())
}

async fn download_sha256_in_pool(
    sha256: &str,
    filename: &str,
    base_url: &str,
) -> anyhow::Result<()> {
    let final_dest: String = {
        let mut tmp: String = String::from(STORE);
        tmp.push('/');
        tmp.push_str(sha256);
        tmp
    };

    if tokio::fs::try_exists(final_dest.as_str()).await? {
        println!("{} already exists", final_dest);
        return Ok(());
    }

    let dest: String = {
        let mut tmpstr: String = String::from(TMP);
        tmpstr.push('/');
        tmpstr.push_str(sha256);
        tmpstr
    };

    let url: String = {
        let mut ret = String::from(base_url);
        ret.push('/');
        ret.push_str(filename);
        ret
    };

    const num_tries: u8 = 4 as u8;

    for _ in 0..num_tries {
        match download(url.as_str(), dest.as_str()).await {
            Err(_) => {
                println!("Failed downloading, trying again {}", filename);
            }
            Ok(_) => {
                let hash = sha256_digest(&dest).await?;
                if sha256.eq(hash.as_str()) {
                    match tokio::fs::rename(dest.as_str(), final_dest.as_str()).await {
                        Err(_) => {
                            println!("Failed to move {} to {}", dest, final_dest);
                        }
                        Ok(_) => {
                            return Ok(());
                        }
                    };
                } else {
                    println!("Hash did not match, try downloading again later...");
                    tokio::fs::remove_file(&dest).await?;
                }
            }
        }
    }

    return Err(anyhow::format_err!(
        "Failed to download the file {}",
        filename
    ));
}

async fn download_package_list_in_pool(
    inputs: std::sync::Arc<Vec<package_pair>>,
    base_2: std::sync::Arc<Vec<&str>>,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> anyhow::Result<()> {
    const batch_size: u64 = 2 as u64;
    loop {
        let begin = counter.fetch_add(batch_size, std::sync::atomic::Ordering::Relaxed) as usize;
        if begin < inputs.len() {
            let end = std::cmp::min(begin + batch_size as usize, inputs.len());
            for i in begin..end {
                let item = &inputs[i];
                let index = i;
                for num_tries in 0..base_2.len() {
                    let url = base_2[(index + num_tries) % base_2.len()];
                    match download_sha256_in_pool(&item.sha256, &item.filename, url).await {
                        Err(e) => {
                            println!("Failed to download the file {} from mirror {} due to {}, trying with a different mirror", item.filename, url, e);
                        }
                        Ok(_) => {
                            println!("Downloaded the file {}", item.filename);
                            break;
                        }
                    }
                }
            }
        } else {
            break;
        }
    }
    Ok(())
}

pub async fn download_pool() -> anyhow::Result<()> {
    tokio::fs::create_dir_all(STORE).await?;
    tokio::fs::create_dir_all(TMP).await?;

    let base_1 = read_list_url_mirrors().await?;
    let base_2: Vec<&str> = base_1.split('\n').filter(|x| x.len() > 7).collect();
    let num_threads = map_num_url_to_num_threads((&base_2).len() as u16);
    let urls = std::sync::Arc::new(base_2);
    let meta_data = std::sync::Arc::new(read_packages().await?);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut handles = Vec::new();

    for _ in 0..num_threads {
        handles.push(download_package_list_in_pool(
            std::sync::Arc::clone(&meta_data),
            std::sync::Arc::clone(&urls),
            std::sync::Arc::clone(&counter),
        ));
    }

    futures::future::join_all(handles).await;

    return Ok(());
}

pub async fn download_dist() -> anyhow::Result<()> {
    let base = read_list_url_mirrors().await?;
    println!("base: {:?}", base);
    let base_s: Vec<&str> = base.split('\n').collect();
    println!("base_s: {:?}", base_s);
    let mut base = String::from(base_s[0]);
    base.push('/');

    let list_dist_packages = read_list_dist_packages().await?;
    println!("1");

    async fn link_slave(filename: &str, url: &str) -> anyhow::Result<()> {
        mkdir(filename).await?;
        link_pool_in_dist(filename).await;
        download(url, filename).await
    }

    let files: Vec<&str> = list_dist_packages
        .split('\n')
        .filter(|x| x.len() > 0)
        .collect();

    println!("files: {:?}", files);

    let urls: Vec<String> = files
        .iter()
        .map(|x| {
            let mut url: String = base.clone();
            url.push_str(x);
            return url;
        })
        .collect();

    println!("urls: {:?}", urls);

    let mut handles = Vec::new();
    for (file, url) in files.iter().zip(urls.iter()) {
        let tmp = link_slave(file, url);
        handles.push(tmp);
    }

    const batch_size: usize = 16;

    let results = futures::stream::iter(handles)
        .buffer_unordered(batch_size)
        .collect::<Vec<_>>()
        .await;
    // let results = futures::future::join_all(handles).await;

    for (result, filename) in results.iter().zip(files.iter()) {
        match result {
            Err(e) => {
                println!("Failed to download dist files {} due to {}", filename, e);
            }
            Ok(()) => {}
        };
    }

    return Ok(());
}

pub async fn make_config() -> anyhow::Result<()> {
    let content: String = tokio::fs::read_to_string("sources.list").await?;

    let lines: Vec<&str> = content
        .split('\n')
        .filter(|x| x.len() > TEXT_DEB.len())
        .collect();

    let mut base_urls = HashSet::new();
    let mut deb_version = HashSet::new();
    let mut deb_components = HashSet::new();

    {
        fn is_deb(inurl: &str) -> bool {
            return inurl.eq(TEXT_DEB);
        }

        fn is_http(inurl: &str) -> bool {
            if inurl.len() > TEXT_HTTPS.len() {
                return inurl[0..TEXT_HTTP.len()].eq(TEXT_HTTP)
                    || inurl[0..TEXT_HTTPS.len()].eq(TEXT_HTTPS);
            } else {
                return false;
            }
        }

        enum LineState {
            LineDeb = 0,
            LineHttp = 1,
            LineVersion = 2,
            LineComponent = 3,
        }

        lines.iter().for_each(|x| {
            let mut state: LineState = LineState::LineDeb;

            x.split(' ').for_each(|x| {
                if x.len() > 0 {
                    match state {
                        LineState::LineDeb => {
                            if is_deb(x) {
                                state = LineState::LineHttp;
                            }
                        }
                        LineState::LineHttp => {
                            if is_http(x) {
                                state = LineState::LineVersion;
                                base_urls.insert(x);
                            }
                        }
                        LineState::LineVersion => {
                            state = LineState::LineComponent;
                            deb_version.insert(x);
                        }
                        LineState::LineComponent => {
                            deb_components.insert(x);
                        }
                    }
                }
            });
        });
    }
    {
        let mut out_string = String::new();

        base_urls.iter().for_each(|x| {
            out_string.push_str(x);
            out_string.push('\n');
        });

        println!("{}", out_string);
        match fs::write("./list.url_mirrors.txt", out_string) {
            Ok(_) => {}
            Err(_) => {
                println!("Unable to write to list.url_mirrors.txt");
            }
        };
    }
    {
        let mut out_data = String::new();

        for v in &deb_version {
            for c in &deb_components {
                println!("v = {}", v);
                println!("c = {}", c);

                let mut tmp_str: String = String::from("dists/");

                tmp_str.push_str(v);
                tmp_str.push('/');

                {
                    let mut release_str = tmp_str.clone();
                    release_str.push_str("Release\n");
                    out_data.push_str(release_str.as_str());
                }

                tmp_str.push_str(c);

                {
                    let mut tmp_str_source: String = tmp_str.clone();

                    tmp_str_source.push_str("/source/Sources");

                    out_data.push_str(tmp_str_source.as_str());
                    out_data.push('\n');
                    {
                        let mut tmp_str_source_gz: String = tmp_str_source.clone();
                        tmp_str_source_gz.push_str(".gz");

                        out_data.push_str(tmp_str_source_gz.as_str());
                        out_data.push('\n');

                        let mut tmp_str_source_xz: String = tmp_str_source.clone();
                        tmp_str_source_xz.push_str(".xz");

                        out_data.push_str(tmp_str_source_xz.as_str());
                        out_data.push('\n');
                    }
                }
                {
                    let mut tmp_str_amd64: String = tmp_str.clone();
                    tmp_str_amd64.push_str("/binary-amd64/Packages");

                    out_data.push_str(tmp_str_amd64.as_str());
                    out_data.push('\n');
                    {
                        let mut tmp_str_amd64_gz: String = tmp_str_amd64.clone();
                        tmp_str_amd64_gz.push_str(".gz");

                        out_data.push_str(tmp_str_amd64_gz.as_str());
                        out_data.push('\n');

                        let mut tmp_str_amd64_xz: String = tmp_str_amd64.clone();
                        tmp_str_amd64_xz.push_str(".xz");

                        out_data.push_str(tmp_str_amd64_xz.as_str());
                        out_data.push('\n');
                    }
                }
                {
                    let mut tmp_str_i386: String = tmp_str.clone();
                    tmp_str_i386.push_str("/binary-i386/Packages");

                    out_data.push_str(tmp_str_i386.as_str());
                    out_data.push('\n');
                    {
                        let mut tmp_str_i386_gz: String = tmp_str_i386.clone();
                        tmp_str_i386_gz.push_str(".gz");

                        out_data.push_str(tmp_str_i386_gz.as_str());
                        out_data.push('\n');

                        let mut tmp_str_i386_xz: String = tmp_str_i386.clone();
                        tmp_str_i386_xz.push_str(".xz");

                        out_data.push_str(tmp_str_i386_xz.as_str());
                        out_data.push('\n');
                    }
                }
            }
        }
        println!("{}", out_data);

        match fs::write("list.dist_packages.txt", out_data) {
            Ok(_) => {}
            Err(_) => {
                println!("Unable to write file list.dist_packages.txt");
            }
        };
    }
    Ok(())
}
