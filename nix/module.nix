# NixOS module for the goweb single sign-on deployment (docs/deployment.md):
# Ory Hydra, the provider, and any number of client apps as containers on the
# host network, bound to loopback, plus optional Cloudflare Tunnel routes and
# PostgreSQL roles. Secrets never enter the Nix store: every service reads an
# environment file at run time (for example a sops-nix secret path).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.goweb;
  inherit (lib) mkOption mkEnableOption mkIf types;

  backend = config.virtualisation.oci-containers.backend;
  engine = lib.getExe pkgs.${backend};
  unit = name: "${backend}-${name}.service";

  hostOf = url: lib.head (lib.splitString "/" (lib.removePrefix "https://" url));
  snake = name: lib.replaceStrings [ "-" ] [ "_" ] name;
  local = port: "http://127.0.0.1:${toString port}";

  hardening = [ "--network=host" "--read-only" "--cap-drop=ALL" "--security-opt=no-new-privileges" ];

  login = lib.optionalAttrs (cfg.registryLogin != null) {
    login = {
      registry = "ghcr.io";
      inherit (cfg.registryLogin) username passwordFile;
    };
  };

  appContainer = { environment, environmentFile, extraEnvironment }: {
    image = cfg.image;
    environment = environment // extraEnvironment;
    environmentFiles = [ environmentFile ];
    extraOptions = hardening;
  } // login;

  common = {
    GOWEB_ENV = "production";
    GOWEB_SESSION_COOKIE_SECURE = "true";
    GOWEB_TRUSTED_PROXY = "127.0.0.1";
    GOWEB_SSO_ISSUER_URL = cfg.issuerUrl;
    GOWEB_MAIL_FROM = cfg.mailFrom;
  };

  clients = lib.filterAttrs (_: c: c.enable) cfg.clients;

  databaseRoles =
    lib.optional cfg.hydra.enable { role = "hydra"; db = "hydra"; password = cfg.hydra.databasePasswordFile; }
    ++ lib.optional cfg.provider.enable { role = "goweb_provider"; db = "goweb_provider"; password = cfg.provider.databasePasswordFile; }
    ++ lib.mapAttrsToList (name: c: { role = "goweb_${snake name}"; db = "goweb_${snake name}"; password = c.databasePasswordFile; }) clients;

  enabledPorts =
    lib.optionals cfg.hydra.enable [ cfg.hydra.publicPort cfg.hydra.adminPort ]
    ++ lib.optional cfg.provider.enable cfg.provider.port
    ++ lib.mapAttrsToList (_: c: c.port) clients;

  containerUnits =
    lib.optional cfg.hydra.enable (unit "goweb-hydra")
    ++ lib.optional cfg.provider.enable (unit "goweb-provider")
    ++ lib.mapAttrsToList (name: _: unit "goweb-client-${name}") clients;

  postgresUnits = if config.systemd.targets ? postgresql then [ "postgresql.target" ] else [ "postgresql.service" ];

  extraEnvironmentOption = mkOption {
    type = types.attrsOf types.str;
    default = { };
    description = "Extra non-secret environment variables for the container.";
  };

  environmentFileOption = description: mkOption {
    type = types.path;
    inherit description;
    example = "/run/secrets/goweb-provider-env";
  };

  databasePasswordFileOption = mkOption {
    type = types.nullOr types.path;
    default = null;
    description = "File with the database role's password. Required when services.goweb.database.manage is on.";
  };
in
{
  options.services.goweb = {
    image = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "ghcr.io/tewecske/goweb:0123456789abcdef0123456789abcdef01234567";
      description = "goweb image for the provider and every client. Pin a commit tag.";
    };

    issuerUrl = mkOption {
      type = types.str;
      default = "";
      example = "https://sso.example.com";
      description = "Hydra's public URL, the OpenID Connect issuer (https, no trailing slash).";
    };

    providerUrl = mkOption {
      type = types.str;
      default = "";
      example = "https://auth.example.com";
      description = "The provider's public URL (https, no trailing slash).";
    };

    mailFrom = mkOption {
      type = types.str;
      default = "";
      example = "no-reply@example.com";
      description = "Sender address on a domain verified in Resend.";
    };

    registryLogin = mkOption {
      default = null;
      description = "Credentials for pulling a private image from ghcr.io.";
      type = types.nullOr (types.submodule {
        options = {
          username = mkOption { type = types.str; };
          passwordFile = mkOption { type = types.path; };
        };
      });
    };

    hydra = {
      enable = mkEnableOption "Ory Hydra";
      image = mkOption { type = types.str; default = "oryd/hydra:v26.2.0"; };
      publicPort = mkOption { type = types.port; default = 24444; };
      adminPort = mkOption { type = types.port; default = 24445; };
      environmentFile = environmentFileOption "File with DSN, SECRETS_SYSTEM, and SECRETS_COOKIE (see deploy/env/hydra.env.example).";
      databasePasswordFile = databasePasswordFileOption;
      extraEnvironment = extraEnvironmentOption;
    };

    provider = {
      enable = mkEnableOption "the single sign-on provider";
      port = mkOption { type = types.port; default = 28080; };
      environmentFile = environmentFileOption "File with GOWEB_DATABASE_URL, GOWEB_SESSION_SECRET, and GOWEB_RESEND_API_KEY.";
      databasePasswordFile = databasePasswordFileOption;
      extraEnvironment = extraEnvironmentOption;
    };

    clients = mkOption {
      default = { };
      description = "Client apps, by name (a-z, 0-9, -).";
      type = types.attrsOf (types.submodule {
        options = {
          enable = mkOption { type = types.bool; default = true; };
          publicUrl = mkOption { type = types.str; example = "https://notes.example.com"; };
          port = mkOption { type = types.port; example = 28081; };
          sessionLifetime = mkOption { type = types.str; default = "8h"; };
          environmentFile = environmentFileOption "File with GOWEB_DATABASE_URL, GOWEB_SESSION_SECRET, GOWEB_RESEND_API_KEY, GOWEB_SSO_CLIENT_ID, and GOWEB_SSO_CLIENT_SECRET.";
          databasePasswordFile = databasePasswordFileOption;
          extraEnvironment = extraEnvironmentOption;
        };
      });
    };

    cloudflared = {
      enable = mkEnableOption "Cloudflare Tunnel routes for Hydra, the provider, and every client";
      tunnelId = mkOption { type = types.str; example = "00000000-0000-0000-0000-000000000000"; };
      credentialsFile = mkOption { type = types.path; example = "/run/secrets/cloudflared-credentials"; };
    };

    database.manage = mkEnableOption "creating the PostgreSQL roles and databases (hydra, goweb_provider, goweb_<client>) and setting their passwords";
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !(cfg.hydra.enable || cfg.provider.enable || clients != { }) || (cfg.issuerUrl != "" && cfg.providerUrl != "");
          message = "services.goweb: set issuerUrl and providerUrl.";
        }
        {
          assertion = !(cfg.provider.enable || clients != { }) || (cfg.image != null && cfg.mailFrom != "");
          message = "services.goweb: set image and mailFrom for the provider and client apps.";
        }
        {
          assertion = lib.length enabledPorts == lib.length (lib.unique enabledPorts);
          message = "services.goweb: two services use the same port.";
        }
        {
          assertion = lib.all (name: builtins.match "[a-z0-9-]+" name != null) (lib.attrNames cfg.clients);
          message = "services.goweb.clients: names may only use a-z, 0-9, and -.";
        }
        {
          assertion = !cfg.database.manage || (config.services.postgresql.enable && lib.all (r: r.password != null) databaseRoles);
          message = "services.goweb.database.manage needs services.postgresql.enable and a databasePasswordFile for every enabled service.";
        }
      ];
    }

    (mkIf cfg.hydra.enable {
      virtualisation.oci-containers.containers.goweb-hydra = {
        image = cfg.hydra.image;
        cmd = [ "serve" "all" "--config" "/etc/hydra/hydra.yml" ];
        volumes = [ "${../deploy/hydra/hydra.yml}:/etc/hydra/hydra.yml:ro" ];
        environment = {
          SERVE_PUBLIC_HOST = "127.0.0.1";
          SERVE_PUBLIC_PORT = toString cfg.hydra.publicPort;
          SERVE_ADMIN_PORT = toString cfg.hydra.adminPort;
          URLS_SELF_ISSUER = cfg.issuerUrl;
          URLS_LOGIN = "${cfg.providerUrl}/sso/login";
          URLS_CONSENT = "${cfg.providerUrl}/sso/consent";
          URLS_LOGOUT = "${cfg.providerUrl}/sso/logout";
          URLS_POST_LOGOUT_REDIRECT = "${cfg.providerUrl}/en/sign-in";
          URLS_ERROR = "${cfg.providerUrl}/sso/error";
        } // cfg.hydra.extraEnvironment;
        environmentFiles = [ cfg.hydra.environmentFile ];
        extraOptions = hardening;
      };

      # Hydra's schema is migrated before every start, so an image upgrade
      # needs no manual step.
      systemd.services.goweb-hydra-migrate = {
        description = "Apply Ory Hydra database migrations";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ] ++ lib.optionals cfg.database.manage [ "goweb-db-init.service" ];
        before = [ (unit "goweb-hydra") ];
        requiredBy = [ (unit "goweb-hydra") ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = lib.escapeShellArgs [
            engine "run" "--rm" "--network=host" "--env-file" (toString cfg.hydra.environmentFile)
            cfg.hydra.image "migrate" "sql" "up" "-e" "--yes"
          ];
        };
      };
      systemd.services.${lib.removeSuffix ".service" (unit "goweb-hydra")}.requires = [ "goweb-hydra-migrate.service" ];
    })

    (mkIf cfg.provider.enable {
      virtualisation.oci-containers.containers.goweb-provider = appContainer {
        environment = common // {
          GOWEB_AUTH_MODE = "provider";
          GOWEB_HTTP_ADDR = "127.0.0.1:${toString cfg.provider.port}";
          GOWEB_PUBLIC_URL = cfg.providerUrl;
          GOWEB_HYDRA_ADMIN_URL = local cfg.hydra.adminPort;
          GOWEB_EMAIL_CONFIRMATION_REQUIRED = "true";
        };
        environmentFile = cfg.provider.environmentFile;
        extraEnvironment = cfg.provider.extraEnvironment;
      };
    })

    {
      virtualisation.oci-containers.containers = lib.mapAttrs' (name: c: lib.nameValuePair "goweb-client-${name}" (appContainer {
        environment = common // {
          GOWEB_AUTH_MODE = "client";
          GOWEB_HTTP_ADDR = "127.0.0.1:${toString c.port}";
          GOWEB_PUBLIC_URL = c.publicUrl;
          GOWEB_SESSION_LIFETIME = c.sessionLifetime;
          GOWEB_SSO_ACCOUNT_URL = "${cfg.providerUrl}/en/account/settings";
        };
        environmentFile = c.environmentFile;
        extraEnvironment = c.extraEnvironment;
      })) clients;
    }

    (mkIf cfg.cloudflared.enable {
      services.cloudflared = {
        enable = true;
        tunnels.${cfg.cloudflared.tunnelId} = {
          credentialsFile = cfg.cloudflared.credentialsFile;
          default = "http_status:404";
          ingress =
            lib.optionalAttrs cfg.hydra.enable { ${hostOf cfg.issuerUrl} = local cfg.hydra.publicPort; }
            // lib.optionalAttrs cfg.provider.enable { ${hostOf cfg.providerUrl} = local cfg.provider.port; }
            // lib.mapAttrs' (_: c: lib.nameValuePair (hostOf c.publicUrl) (local c.port)) clients;
        };
      };
    })

    (mkIf cfg.database.manage {
      systemd.services.goweb-db-init = {
        description = "Create goweb PostgreSQL roles and databases";
        wantedBy = [ "multi-user.target" ];
        requires = postgresUnits;
        after = postgresUnits;
        before = containerUnits;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "postgres";
          LoadCredential = map (r: "${r.role}:${toString r.password}") databaseRoles;
        };
        # Idempotent: creates what is missing, resets each role's password to
        # the file's value, and lets only the role connect to its database.
        script = lib.concatMapStringsSep "\n" (r: ''
          ${config.services.postgresql.package}/bin/psql -X -v ON_ERROR_STOP=1 -d postgres <<'SQL'
          \set pw `cat "$CREDENTIALS_DIRECTORY/${r.role}"`
          SELECT 'CREATE ROLE "${r.role}" LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${r.role}') \gexec
          ALTER ROLE "${r.role}" PASSWORD :'pw';
          SELECT 'CREATE DATABASE "${r.db}" OWNER "${r.role}"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${r.db}') \gexec
          REVOKE CONNECT ON DATABASE "${r.db}" FROM PUBLIC;
          SQL
        '') databaseRoles;
      };
    })

    (mkIf (cfg.database.manage && containerUnits != [ ]) {
      systemd.services = lib.genAttrs (map (u: lib.removeSuffix ".service" u) containerUnits) (_: {
        requires = [ "goweb-db-init.service" ];
        after = [ "goweb-db-init.service" ];
      });
    })
  ];
}
