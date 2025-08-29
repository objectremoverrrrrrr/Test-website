
{ pkgs }: {
  deps = [
    pkgs.nodejs_20
    pkgs.npm-check-updates
    pkgs.nodePackages.nodemon
  ];
  
  env = {
    NODE_ENV = "development";
  };
}
