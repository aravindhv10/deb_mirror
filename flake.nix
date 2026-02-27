{
  description = "A Rust-based Debian mirror tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "deb_mirror";
          version = "0.1.0"; # Adjust based on the actual version in Cargo.toml

          # If the flake is inside the repo, use ./.; 
          # otherwise, fetch from GitHub
          src = ./.; 

          # This hash ensures reproducibility. If you change dependencies, 
          # Nix will give you a new hash to put here.
          # You can set this to lib.fakeHash initially to find the correct one.
          cargoHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            rust-analyzer
            pkg-config
            openssl
          ];
        };
      }
    );
}
