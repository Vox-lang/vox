{
  description = "Vox - a systems level compiler for a sentence-based English syntax";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "vox";
          version = "0.4.9";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # vox shells out to nasm/ld only when compiling a user's .vox
          # program, not to build vox itself -- but the test suite's
          # integration tests do that (e.g. p210_map_preservation invokes
          # `vox --shared`), so nasm/binutils are needed in the sandbox for
          # `cargo test` during the check phase too, not just at the
          # installed binary's runtime (handled by postFixup below).
          nativeBuildInputs = [ pkgs.makeWrapper pkgs.nasm pkgs.binutils ];

          postFixup = ''
            wrapProgram $out/bin/vox \
              --set VOX_CORE_PATH $out/share/vox/coreasm \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nasm pkgs.binutils ]}
          '';

          postInstall = ''
            mkdir -p $out/share/vox
            cp -r coreasm $out/share/vox/coreasm
          '';

          meta = with pkgs.lib; {
            description = "A systems level compiler for Vox (sentence based code)";
            homepage = "https://github.com/Vox-lang/vox";
            license = licenses.gpl3Plus;
            mainProgram = "vox";
            platforms = platforms.linux;
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.nasm pkgs.binutils ];
        };
      });
}
