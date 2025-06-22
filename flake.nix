{
  description = "SMPP dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix.url = "github:nix-community/fenix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        rust-toolchain = fenix.packages.${system}.stable.defaultToolchain;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rust-toolchain
            pkgs.cargo-outdated
            pkgs.nixd
          ];
        };
      }
    );
}
