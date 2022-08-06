{
  description = "Nix flake to pin everything in place for the rust dev env.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nixpkgs-21.url = "github:NixOS/nixpkgs/nixos-21.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

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
        rust-custom-toolchain = (pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.default.override {
            extensions = [ "rust-src" "rustfmt" "llvm-tools-preview" "rust-analyzer-preview" "miri" ];
            targets = [ "thumbv7em-none-eabihf" ];
          }));
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

          devShell = target-pkgs.mkShell {
            buildInputs = [
              pkgs.glibc_multi
            ];

            nativeBuildInputs = with pkgs; [
              rust-custom-toolchain
              probe-run

              valgrind
            ];

            # manually define llvm lib location for bindgen (here too?)
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

            # cflags interacts with cc-rs to inject libc include paths
            CFLAGS = [ "-I${pkgs.glibc.dev}/include/" ];
            # bindgen_extra_clang_args is almost identical, but interacts with bindgen to inject libc include paths
            BINDGEN_EXTRA_CLANG_ARGS = [
              "-I${pkgs.glibc.dev}/include/"
              "-I${pkgs.llvmPackages_13.clang-unwrapped.lib}/lib/clang/13.0.1/include/"
              "-I${pkgs.llvmPackages.libclang.lib}/lib"
            ];

            LD_LIBRARY_PATH = "${
              pkgs.lib.makeLibraryPath [
                # llvm with the embedded target arch
                pkgs.llvmPackages.libclang.lib
              ]
            }";

            DEFMT_LOG = "trace";

            CARGO_NET_GIT_FETCH_WITH_CLI = "true";
            RUST_BACKTRACE = 1;
          };

          checks = let
            craneLib =
              (inputs.crane.mkLib pkgs).overrideToolchain rust-custom-toolchain;
            # cargoArtifacts = craneLib.buildDepsOnly {
            #   inherit src;
            #   hardeningDisable = [ "all" ];

            #   # manually define llvm lib location for bindgen (here too?)
            #   LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

            #   # cflags interacts with cc-rs to inject libc include paths
            #   CFLAGS = [ "-I${pkgs.glibc.dev}/include/" ];
            #   # bindgen_extra_clang_args is almost identical, but interacts with bindgen to inject libc include paths
            #   BINDGEN_EXTRA_CLANG_ARGS = [
            #     "-I${pkgs.glibc.dev}/include/"
            #     "-I${pkgs.llvmPackages_13.clang-unwrapped.lib}/lib/clang/13.0.1/include/"
            #   ];
            # };
            common-build-args = {
              src = ./.;
              hardeningDisable = [ "all" ];

              # manually define llvm lib location for bindgen (here too?)
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

              LD_LIBRARY_PATH = "${
                pkgs.lib.makeLibraryPath [
                  # llvm with the embedded target arch
                  pkgs.llvmPackages.libclang.lib
                ]
              }";

              # cflags interacts with cc-rs to inject libc include paths
              CFLAGS = [ "-I${pkgs.glibc.dev}/include/" ];
              # bindgen_extra_clang_args is almost identical, but interacts with bindgen to inject libc include paths
              BINDGEN_EXTRA_CLANG_ARGS = [
                "-I${pkgs.glibc.dev}/include/"
                "-I${pkgs.llvmPackages_13.clang-unwrapped.lib}/lib/clang/13.0.1/include/"
              ];

            };
            cargoArtifacts = craneLib.buildDepsOnly ({
              cargoBuildCommand = "cargo build --release -p optiga-m";
            } // common-build-args);

            build-tests = craneLib.cargoNextest ({
              cargoArtifacts = null;
              RUSTFLAGS = [ "-Zsanitizer=address" ];

              cargoNextestExtraArgs = "-p optiga-m";
              doInstallCargoArtifacts = true;
            } // common-build-args);
          in {
            inherit build-tests;
          };
        }
    );
}
