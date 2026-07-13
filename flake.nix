{
  description = "Development toolchain for the icmp-socket crate";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = with pkgs; (pkgs.mkShell {
          packages = [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];
        });
      });
}
