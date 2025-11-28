extern crate rayon;
extern crate reqwest;
extern crate sha256;
extern crate substring;

use rayon::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use substring::Substring;

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

const NUM_THREADS: usize = 24;

fn read_file(name_file: &str) -> String {
    let mut data = String::new();

    match File::open(name_file) {
        Ok(mut file) => {
            match file.read_to_string(&mut data) {
                Ok(_) => {}
                Err(_) => {
                    println!("Failed to read the file {}", name_file);
                }
            }

            return data;
        }
        Err(_) => {
            println!("Failed to open the file {}", name_file);
            return data;
        }
    };
}

fn read_list_url_mirrors() -> String {
    read_file("list.url_mirrors.txt")
}

fn read_list_dist_packages() -> String {
    read_file("list.dist_packages.txt")
}

fn mkdir_slave(name_dir: &str) {
    match fs::create_dir(name_dir) {
        Ok(_) => {
            println!("Created directory {}", name_dir);
        }
        Err(_) => {
            println!("Failed to create directory {}", name_dir);
        }
    };
}

fn mkdir(name_dir: &str) {
    let name_dir_s: Vec<&str> = name_dir.split('/').collect();
    let mut path: String = ".".to_string();

    mkdir_slave(path.as_str());

    for i in 0..name_dir_s.len() - 1 {
        path.push('/');
        path.push_str(name_dir_s[i]);
        mkdir_slave(path.as_str());
    }
}

fn _download_wget(url: &str, file_name: &str) -> Result<u8, u8> {
    let result = Command::new("wget")
        .arg("-c")
        .arg(url)
        .arg("-O")
        .arg(file_name)
        .status();

    match result {
        Ok(o) => {
            println!("Success: {} downloading {} into {}", o, url, file_name);
            return Ok(0);
        }
        Err(e) => {
            println!("Failed: {} downloading {} into {}", e, url, file_name);
            return Err(1);
        }
    }
}

fn _download_ruget(url: &str, file_name: &str) -> Result<u8, u8> {
    let result = Command::new("ruget")
        .arg(url)
        .arg("-o")
        .arg(file_name)
        .status();

    match result {
        Ok(o) => {
            println!("Success: {} downloading {} into {}", o, url, file_name);
            return Ok(0);
        }
        Err(e) => {
            println!("Failed: {} downloading {} into {}", e, url, file_name);
            return Err(1);
        }
    }
}

#[tokio::main]
async fn _download_reqwest(url: &str, file_name: &str) -> Result<u8, u8> {
    match File::create(file_name) {
        Ok(mut dest) => {
            println!("Downloading {}", url);

            let response = reqwest::get(url);
            let response = response.await;

            match response {
                Ok(o) => {
                    let response = o;
                    let content = response.bytes();
                    let content = content.await;

                    match content {
                        Ok(content) => {
                            let mut pos: usize = 0;
                            while pos < content.len() {
                                match dest.write(&content[pos..]) {
                                    Ok(o) => {
                                        pos += o;
                                    }
                                    Err(_) => {
                                        println!("Failed to write data into the file");
                                        return Err(4);
                                    }
                                }
                            }
                            println!("Successfully downloaded the file {}", file_name);
                            return Ok(0);
                        }
                        Err(_) => {
                            println!("Failed to get content in download {}", url);
                            return Err(3);
                        }
                    };
                }
                Err(_) => {
                    println!("Failed response in download {}", url);
                    return Err(2);
                }
            };
        }
        Err(_) => {
            println!("Failed to create file {}", file_name);
            return Err(1);
        }
    };
}

fn download(url: &str, file_name: &str) -> Result<u8, u8> {
    _download_reqwest(url, file_name)
}

fn do_link(sha: &str, loc: &str) {
    mkdir(loc);
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
    match std::os::unix::fs::symlink(&dest, &loc) {
        Ok(_) => {
            println!("linked {}", dest);
        }
        Err(_) => {
            println!("Failed to link {}", dest);
        }
    };
}

fn read_packages() -> HashMap<String, (String, String)> {
    let files_1 = read_list_dist_packages();
    println!("{:?}", files_1);
    let mut files_2: String = String::new();

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

    files_1
        .split('\n')
        .filter(|x| has_packages(x))
        .for_each(|x| {
            println!("Got package {}", x);
            files_2.push_str(read_file(x).as_str());
            files_2.push('\n');
        });

    let mut meta_data: HashMap<String, (String, String)> = HashMap::new();

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
                    meta_data.insert(sha256.clone(), (filename.clone(), version.clone()));
                }
            }
        };
    });

    return meta_data;
}

fn link_pool_in_dist(file_name: &str) {
    let loc: Vec<&str> = file_name.split('/').collect();

    let mut out = String::new();

    for i in 0..loc.len() - 1 {
        if !loc[i].eq(".") {
            out.push_str(loc[i]);
            out.push('/');

            let mut dest: String = out.clone();
            dest.push_str("pool");

            match std::os::unix::fs::symlink("../pool", &dest) {
                Ok(_) => {
                    println!("linked pool in dist {}", &dest);
                }
                Err(_) => {
                    println!("failed link pool in dist {}", &dest);
                }
            };
        }
    }
}

pub fn link_pool() {
    {
        let files = read_list_dist_packages();
        files.split('\n').filter(|x| x.len() > 0).for_each(|x| {
            mkdir(x);
            link_pool_in_dist(x);
        });
    }

    let meta_data = read_packages();

    meta_data
        .par_iter()
        .for_each(|(sha256, (filename, _version))| {
            do_link(sha256, filename);
        })
}

pub fn clean_sha() {
    let meta_data = read_packages();

    match fs::rename(STORE, WASTE) {
        Ok(_) => {
            mkdir_slave(STORE);
            meta_data
                .par_iter()
                // .for_each(|(sha256, (_filename, _version))| {
                .for_each(|(sha256, _a)| {
                    let mut src = String::from(WASTE);
                    src.push('/');
                    src.push_str(sha256);

                    let mut dst = String::from(STORE);
                    dst.push('/');
                    dst.push_str(sha256);

                    match fs::rename(src, dst) {
                        Ok(_) => {}
                        Err(_) => {
                            println!("Failed in renaming step...");
                        }
                    };
                });
        }
        Err(_) => {
            println!("Failed to move sha256 to waste");
        }
    }
}

pub fn download_pool() {
    mkdir_slave(STORE);
    mkdir_slave(TMP);

    let base_1 = read_list_url_mirrors();
    let base_2: Vec<&str> = base_1.split('\n').filter(|x| x.len() > 7).collect();
    println!("{:?}", base_2);

    let meta_data = read_packages();
    println!("{:?}", meta_data);
    let m = Mutex::new(0);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(NUM_THREADS)
        .build()
        .unwrap();

    pool.install(|| {
        meta_data
            .par_iter()
            .for_each(|(sha256, (filename, _version))| {
                let mut exp_dest: String = String::from(STORE);
                exp_dest.push('/');
                exp_dest.push_str(sha256);

                if !Path::new(exp_dest.as_str()).exists() {
                    let dest: String = {
                        let mut tmpstr: String = String::from(TMP);
                        tmpstr.push('/');
                        tmpstr.push_str(sha256);
                        tmpstr
                    };

                    let mut do_loop: u8 = 4;

                    while do_loop > 0 {
                        let url: String = {
                            let index: usize = {
                                let mut num = m.lock().unwrap();
                                let old = *num % base_2.len();
                                *num = (*num + 1) % base_2.len();
                                old
                            };

                            let mut ret = String::from(base_2[index]);

                            ret.push('/');
                            ret.push_str(filename);
                            ret
                        };

                        match download(url.as_str(), dest.as_str()) {
                            Ok(_) => {
                                let data = std::fs::read(&dest).unwrap();
                                let data: &[u8] = &data;

                                let hash = sha256::digest(data);
                                let validity: bool = sha256.eq(hash.as_str());

                                if validity {
                                    let final_dest: String = {
                                        let mut tmpstr: String = String::from(STORE);
                                        tmpstr.push('/');
                                        tmpstr.push_str(hash.as_str());
                                        tmpstr
                                    };

                                    match fs::rename(dest.as_str(), final_dest.as_str()) {
                                        Ok(_) => {
                                            do_loop = 0;
                                        }
                                        Err(_) => {
                                            println!("Failed to move {} to {}", dest, final_dest);
                                        }
                                    };
                                } else {
                                    do_loop -= 1;
                                    println!("Hash did not match, try downloading again later...");
                                }
                            }
                            Err(_) => {
                                println!("Failed downloading, trying again {}", filename);
                            }
                        };
                    }
                } else {
                    println!("{} already exists", exp_dest);
                }
            });
    });
}

pub fn download_dist() {
    let base = read_list_url_mirrors();
    let base_s: Vec<&str> = base.split('\n').collect();
    let mut base = String::from(base_s[0]);
    base.push('/');

    let files = read_list_dist_packages();
    let files_s: Vec<&str> = files
        .split('\n')
        .filter(|x| x.len() > 0)
        .map(|x|{
            mkdir(x);
            link_pool_in_dist(x);
            x
        })
        .collect();

    files_s.par_iter().for_each(|x| {
        let mut url: String = base.clone();
        url.push_str(x);

        let mut do_loop: bool = true;

        while do_loop {
            match download(url.as_str(), x) {
                Ok(_) => {
                    do_loop = false;
                }
                Err(_) => {
                    println!("Downloading {} failed, trying again...", url);
                }
            };
        }
    });
}

pub fn make_config() {
    let content: String = read_file("sources.list");
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
}
