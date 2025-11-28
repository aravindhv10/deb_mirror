{
  lib,
  stdenv,
  rustPlatform,
  fetchurl,
  installShellFiles,
  openssl,
  pkg-config
}:

rustPlatform.buildRustPackage rec {
  pname = "deb_mirror";
  version = "1.0.0";
  src = fetchurl {url = "https://gitlab.com/aravindhv101/deb_mirror/-/archive/7812231bd0a6ad43838a770bddb54c1dcd995ffd/deb_mirror-7812231bd0a6ad43838a770bddb54c1dcd995ffd.tar.gz" ; hash = "";};

  useFetchCargoVendor = true;
  cargoHash = "sha256-+0rXnATqHE+NdD9jpu/rdc+nmLqF9lX3g5YpT212mVo=" ;

  nativeBuildInputs = [ installShellFiles openssl pkg-config ];

  buildInputs = [ openssl pkg-config ];

  meta = with lib; {
    description = "debian repo mirror tool";
    homepage = "https://gitlab.com/aravindhv101/deb_mirror";
    mainProgram = "deb_mirror";
    platforms = lib.platforms.all;
  };
}