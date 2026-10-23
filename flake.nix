{
  description = "goweb: NixOS module that runs Ory Hydra, the single sign-on provider, and client apps as containers";

  outputs = { self }: {
    nixosModules.default = import ./nix/module.nix;
    nixosModules.goweb = self.nixosModules.default;
  };
}
