{
  inputs =
    {
      nixpkgs = { url = "github:NixOS/nixpkgs/nixos-unstable"; };
      flake-utils = { url = "github:numtide/flake-utils"; };
      rust-overlay =
        {
          url = "github:oxalica/rust-overlay";
          inputs = {
            nixpkgs.follows = "nixpkgs";
            flake-utils.follows = "flake-utils";
          };
        };
      crane = {
        url = "github:ipetkov/crane";
        inputs = {
          nixpkgs.follows = "nixpkgs";
        };
      };
    };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;

          buildInputs = with pkgs;
            [ ];
          nativeBuildInputs = with pkgs; [ clang_15 mold rustToolchain ]
            ++ lib.optionals pkgs.stdenv.isLinux [ autoPatchelfHook ]
            ++ lib.optionals pkgs.stdenv.isDarwin
            (with pkgs.darwin.apple_sdk.frameworks; [
              CoreFoundation
              CoreServices
              SystemConfiguration
              Security
            ]);
          commonArgs = {
            pname = "mevi";
            version = "latest";
            strictDeps = true;
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            inherit src buildInputs nativeBuildInputs;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          bin = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        with pkgs;
        {
          checks = {
            inherit bin;

            told-clippy = craneLib.cargoClippy
              (commonArgs // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets";
              });
          };
          packages = {
            inherit bin;
            default = bin;
          };
          devShells.default = mkShell {
            inputsFrom = [ bin ];
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };
        }
      );
}
