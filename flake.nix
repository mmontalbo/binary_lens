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
        pyPkgs = pkgs.python312Packages;
        jpype1Wheel =
          if pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64
          then "${pkgs.ghidra}/lib/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
          else if pkgs.stdenv.isLinux && pkgs.stdenv.isAarch64
          then "${pkgs.ghidra}/lib/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
          else if pkgs.stdenv.isDarwin
          then "${pkgs.ghidra}/lib/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-1.5.2-cp312-cp312-macosx_10_9_universal2.whl"
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
        pyghidraWheel = "${pkgs.ghidra}/lib/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.0.0-py3-none-any.whl";
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
          pyghidraPkg
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          packages =
            [
              pkgs.jdk21
              pythonEnv
              pkgs.ripgrep
              pkgs.jq
              pkgs.stdenv.cc.cc.lib
            ]
            ++ lib.optionals pkgs.stdenv.isLinux [
              pkgs.ghidra
            ];
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ];
        };

        formatter = pkgs.alejandra;
      });
}
