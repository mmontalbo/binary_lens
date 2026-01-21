{
  description = "Binary Lens reproducible dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        ghidraPkg = pkgs.ghidra;
        excludedNames = [
          ".git"
          "out"
          "ghidra_projects"
          ".direnv"
          "result"
          ".ruff_cache"
          ".pytest_cache"
          ".mypy_cache"
          "__pycache__"
        ];
        cleanedSrc = lib.cleanSourceWith {
          src = self;
          filter = path: type:
            let
              base = builtins.baseNameOf path;
            in
              !(lib.elem base excludedNames);
        };
        ghidraInstallDir = "${ghidraPkg}/lib/ghidra";
        ghidraHeadless = "${ghidraInstallDir}/support/analyzeHeadless";
        binaryLensCli = pkgs.writeShellApplication {
          name = "binary_lens";
          runtimeInputs = [
            pkgs.jdk21
            pkgs.stdenv.cc.cc.lib
            pythonEnv
          ] ++ lib.optionals pkgs.stdenv.isLinux [
            ghidraPkg
          ];
          text = ''
            set -euo pipefail

            root="''${BINARY_LENS_ROOT:-${cleanedSrc}}"
            cli_path="$root/scripts/binary_lens_cli.py"
            if [ ! -f "$cli_path" ]; then
              echo "Could not locate scripts/binary_lens_cli.py. Run from repo root or set BINARY_LENS_ROOT." >&2
              exit 1
            fi

            export BINARY_LENS_ROOT="$root"
            ${lib.optionalString pkgs.stdenv.isLinux ''
            if [ -z "''${GHIDRA_INSTALL_DIR:-}" ]; then
              export GHIDRA_INSTALL_DIR="${ghidraInstallDir}"
            fi
            if [ -z "''${BINARY_LENS_GHIDRA_HEADLESS:-}" ]; then
              export BINARY_LENS_GHIDRA_HEADLESS="${ghidraHeadless}"
            fi
            if [ -z "''${BINARY_LENS_GHIDRA_VERSION:-}" ]; then
              export BINARY_LENS_GHIDRA_VERSION="${ghidraPkg.version}"
            fi
            ''}
            libdir="${pkgs.stdenv.cc.cc.lib}/lib"
            case ":''${LD_LIBRARY_PATH:-}:" in
              *":$libdir:"*) ;;
              *)
                if [ -z "''${LD_LIBRARY_PATH:-}" ]; then
                  export LD_LIBRARY_PATH="$libdir"
                else
                  export LD_LIBRARY_PATH="$libdir:$LD_LIBRARY_PATH"
                fi
                ;;
            esac
            exec python "$cli_path" "$@"
          '';
        };
        pyPkgs = pkgs.python312Packages;
        jpype1Wheel =
          if pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64
          then "${ghidraInstallDir}/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
          else if pkgs.stdenv.isLinux && pkgs.stdenv.isAarch64
          then "${ghidraInstallDir}/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
          else if pkgs.stdenv.isDarwin
          then "${ghidraInstallDir}/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-macosx_10_9_universal2.whl"
          else null;
        jpype1Pkg =
          if jpype1Wheel == null
          then pyPkgs.jpype1
          else pyPkgs.buildPythonPackage {
            pname = "jpype1";
            version = "1.5.2";
            src = jpype1Wheel;
            format = "wheel";
            doCheck = false;
          };
        pyghidraWheel = "${ghidraInstallDir}/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.0.0-py3-none-any.whl";
        pyghidraPkg =
          if lib.hasAttr "pyghidra" pyPkgs
          then pyPkgs.pyghidra
          else pyPkgs.buildPythonPackage {
            pname = "pyghidra";
            version = "3.0.0";
            src = pyghidraWheel;
            format = "wheel";
            propagatedBuildInputs = [
              jpype1Pkg
              pyPkgs.packaging
            ];
            doCheck = false;
          };
        pythonEnv = pkgs.python312.withPackages (ps: [
          ps.pip
          ps.duckdb
          ps.pyarrow
          pyghidraPkg
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          packages =
            [
              pkgs.jdk21
              pkgs.duckdb
              pythonEnv
              pkgs.ruff
              pkgs.ripgrep
              pkgs.stdenv.cc.cc.lib
            ]
            ++ lib.optionals pkgs.stdenv.isLinux [
              ghidraPkg
              binaryLensCli
            ];
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ];
          GHIDRA_INSTALL_DIR = lib.optionalString pkgs.stdenv.isLinux ghidraInstallDir;
          BINARY_LENS_GHIDRA_HEADLESS = lib.optionalString pkgs.stdenv.isLinux ghidraHeadless;
          BINARY_LENS_GHIDRA_VERSION = lib.optionalString pkgs.stdenv.isLinux ghidraPkg.version;
        };

        packages.binary_lens = binaryLensCli;
        apps.binary_lens = flake-utils.lib.mkApp {
          drv = binaryLensCli;
        };

        formatter = pkgs.alejandra;
      });
}
