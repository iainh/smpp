{
  description = "SMPP dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, fenix, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        rust-toolchain = fenix.packages.${system}.stable.toolchain;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust-toolchain
            cargo-outdated
            nixd
          ];
        };
      }
    );
}
