{
  description = "Nix flake to pin everything in place for the rust dev env.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nixpkgs-21.url = "github:NixOS/nixpkgs/nixos-21.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = inputs@{ self, flake-utils, nixpkgs, rust-overlay, nixpkgs-21, ... }:
    flake-utils.lib.eachSystem [ flake-utils.lib.system.x86_64-linux ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        pkgs21 = import nixpkgs-21 {
          inherit system overlays;
        };
        target-pkgs = pkgs.pkgsCross.armhf-embedded;
        target-build-pkgs = target-pkgs.buildPackages;
      in
        rec {
          probe-run = pkgs.rustPlatform.buildRustPackage rec {
            pname = "probe-run";
            version = "0.3.0";

            src = pkgs.fetchFromGitHub {
              owner = "knurling-rs";
              repo = pname;
              rev = "v${version}";
              sha256 = "sha256-gjfd8r64IFG4jPntEJW9XGYPNo7rGs51mohhLozfl2I=";
            };

            cargoSha256 = "sha256-hMQHNRWvAYEaXM5rrynDLpuu96sPEV6rXMVHsfd/y4M=";

            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs; [ libusb1 ];

            meta = with pkgs.lib; {
              description = "Run embedded programs just like native ones.";
              homepage = "https://github.com/knurling-rs/probe-run";
              license = with licenses; [
                asl20 # or
                mit
              ];
              maintainers = with maintainers; [ hoverbear bootstrap-prime ];
            };
          };

          devShell = let
            rust = (pkgs.rust-bin.selectLatestNightlyWith (toolchain:
              toolchain.default.override {
                extensions = [ "rust-src" "rustfmt" "llvm-tools-preview" "rust-analyzer-preview" "miri" ];
                targets = [ "thumbv7em-none-eabihf" ];
              }));
          in target-pkgs.mkShell {
            buildInputs = [
              pkgs.glibc_multi
            ];

            nativeBuildInputs = with pkgs; [
              rust
              probe-run

              valgrind
            ];

            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
                target-build-pkgs.llvmPackages_13.clang-unwrapped.lib
              ]}";
            '';

            LIBC_PATH = "${pkgs.glibc_multi.dev}/include/";
            STDDEF_PATH = "${target-build-pkgs.llvmPackages_13.clang-unwrapped.lib}/lib/clang/13.0.1/include/";

            LIBCLANG_PATH = "${target-build-pkgs.llvmPackages_13.clang-unwrapped.lib}/lib";

            DEFMT_LOG = "trace";

            CARGO_NET_GIT_FETCH_WITH_CLI = "true";
            RUST_BACKTRACE = 1;
          };

          checks = {
            asanbuild_optigam = pkgs.rustPlatform.buildRustPackage {
              pname = "optiga-m";
              version = "2022-06-07";

              buildAndTestSubdir = "./optiga-m";
              src = ./.;

              cargoLock = {
                lockFile = ./Cargo.lock;
              };
              # cargoSha256 = pkgs.lib.fakeSha256;

              CFLAGS = ["-fsanitize=address"];
              CC = "gcc";
              RUSTFLAGS = ["-Zsanitizer=address"];

              release = true;
            };
          };
        }
    );
}
