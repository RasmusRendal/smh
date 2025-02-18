{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    flake-utils,
    nixpkgs,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      pythonEnv = pkgs.python3.withPackages (ps: with ps; [flask signedjson requests gunicorn attr twisted ]);
    in {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [pythonEnv pkgs.matrix-synapse.unwrapped ];
      };
    });
}
