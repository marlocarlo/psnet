//! Technology fingerprint database for server detection.
//!
//! Fingerprints are loaded from `data/fingerprints.json` (embedded at compile time)
//! and parsed once at first access. To add new fingerprints, edit the JSON file —
//! no Rust code changes required.

use std::sync::OnceLock;
use super::types::ServerKind;

// ─── Fingerprint struct (owned data, loaded from JSON) ──────────────────────

/// A single technology fingerprint with detection patterns across multiple signals.
#[derive(Clone, Debug)]
pub struct TechFingerprint {
    pub kind: ServerKind,
    pub priority: u8,
    pub process_names: Vec<String>,
    pub exe_path_contains: Vec<String>,
    pub cmdline_contains: Vec<String>,
    pub cmdline_requires_process: Vec<String>,
    pub http_server_contains: Vec<String>,
    pub http_powered_by_contains: Vec<String>,
    pub http_header_contains: Vec<(String, String)>,
    pub html_title_contains: Vec<String>,
    pub banner_starts_with: Vec<String>,
    pub banner_contains: Vec<String>,
    pub default_ports: Vec<u16>,
    pub version_from_header_prefix: Option<String>,
}

// ─── Embedded JSON database ─────────────────────────────────────────────────

static FINGERPRINTS_JSON: &str = include_str!("../../../data/fingerprints.json");

static FINGERPRINTS: OnceLock<Vec<TechFingerprint>> = OnceLock::new();

/// Get the fingerprint database (parsed once, cached forever).
pub fn fingerprints() -> &'static [TechFingerprint] {
    FINGERPRINTS.get_or_init(|| load_fingerprints(FINGERPRINTS_JSON))
}

// ─── JSON parser ────────────────────────────────────────────────────────────

fn load_fingerprints(json: &str) -> Vec<TechFingerprint> {
    let entries: Vec<serde_json::Value> = serde_json::from_str(json)
        .expect("fingerprints.json: invalid JSON");

    entries
        .into_iter()
        .filter_map(|v| parse_fingerprint(&v))
        .collect()
}

fn parse_fingerprint(v: &serde_json::Value) -> Option<TechFingerprint> {
    let kind_str = v.get("kind")?.as_str()?;
    let kind = parse_server_kind(kind_str)?;
    let priority = v.get("priority").and_then(|p| p.as_u64()).unwrap_or(10) as u8;

    Some(TechFingerprint {
        kind,
        priority,
        process_names: str_array(v, "process_names"),
        exe_path_contains: str_array(v, "exe_path_contains"),
        cmdline_contains: str_array(v, "cmdline_contains"),
        cmdline_requires_process: str_array(v, "cmdline_requires_process"),
        http_server_contains: str_array(v, "http_server_contains"),
        http_powered_by_contains: str_array(v, "http_powered_by_contains"),
        http_header_contains: header_pairs(v, "http_header_contains"),
        html_title_contains: str_array(v, "html_title_contains"),
        banner_starts_with: str_array(v, "banner_starts_with"),
        banner_contains: str_array(v, "banner_contains"),
        default_ports: port_array(v, "default_ports"),
        version_from_header_prefix: v.get("version_from_header_prefix")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
    })
}

fn str_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn port_array(v: &serde_json::Value, key: &str) -> Vec<u16> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default()
}

fn header_pairs(v: &serde_json::Value, key: &str) -> Vec<(String, String)> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|pair| {
                    let arr = pair.as_array()?;
                    if arr.len() >= 2 {
                        Some((
                            arr[0].as_str()?.to_string(),
                            arr[1].as_str()?.to_string(),
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a ServerKind variant name from its Debug representation.
fn parse_server_kind(s: &str) -> Option<ServerKind> {
    Some(match s {
        // Web servers
        "Nginx" => ServerKind::Nginx,
        "Apache" => ServerKind::Apache,
        "IIS" => ServerKind::IIS,
        "Caddy" => ServerKind::Caddy,
        "LiteSpeed" => ServerKind::LiteSpeed,
        "Traefik" => ServerKind::Traefik,

        // App runtimes
        "NodeJs" => ServerKind::NodeJs,
        "Deno" => ServerKind::Deno,
        "Bun" => ServerKind::Bun,
        "Python" => ServerKind::Python,
        "Django" => ServerKind::Django,
        "Flask" => ServerKind::Flask,
        "FastAPI" => ServerKind::FastAPI,
        "Uvicorn" => ServerKind::Uvicorn,
        "Gunicorn" => ServerKind::Gunicorn,
        "Ruby" => ServerKind::Ruby,
        "Rails" => ServerKind::Rails,
        "PhpBuiltIn" => ServerKind::PhpBuiltIn,
        "JavaSpringBoot" => ServerKind::JavaSpringBoot,
        "JavaTomcat" => ServerKind::JavaTomcat,
        "DotNetKestrel" => ServerKind::DotNetKestrel,
        "GoHttp" => ServerKind::GoHttp,
        "RustActix" => ServerKind::RustActix,
        "RustAxum" => ServerKind::RustAxum,

        // Databases
        "PostgreSQL" => ServerKind::PostgreSQL,
        "MySQL" => ServerKind::MySQL,
        "MariaDB" => ServerKind::MariaDB,
        "MongoDB" => ServerKind::MongoDB,
        "Redis" => ServerKind::Redis,
        "SQLite" => ServerKind::SQLite,
        "Memcached" => ServerKind::Memcached,
        "Elasticsearch" => ServerKind::Elasticsearch,
        "ClickHouse" => ServerKind::ClickHouse,
        "CockroachDB" => ServerKind::CockroachDB,

        // Message brokers
        "RabbitMQ" => ServerKind::RabbitMQ,
        "Kafka" => ServerKind::Kafka,
        "NATS" => ServerKind::NATS,
        "Mosquitto" => ServerKind::Mosquitto,

        // Dev tools
        "ViteDevServer" => ServerKind::ViteDevServer,
        "WebpackDevServer" => ServerKind::WebpackDevServer,
        "NextJs" => ServerKind::NextJs,
        "Remix" => ServerKind::Remix,
        "CreateReactApp" => ServerKind::CreateReactApp,
        "AngularCli" => ServerKind::AngularCli,
        "VueCli" => ServerKind::VueCli,
        "SvelteKit" => ServerKind::SvelteKit,
        "Astro" => ServerKind::Astro,
        "Hugo" => ServerKind::Hugo,
        "Gatsby" => ServerKind::Gatsby,
        "Storybook" => ServerKind::Storybook,

        // Infrastructure
        "Docker" => ServerKind::Docker,
        "Kubernetes" => ServerKind::Kubernetes,
        "Prometheus" => ServerKind::Prometheus,
        "Grafana" => ServerKind::Grafana,
        "Jenkins" => ServerKind::Jenkins,
        "GitLabRunner" => ServerKind::GitLabRunner,
        "Consul" => ServerKind::Consul,
        "Vault" => ServerKind::Vault,
        "MinIO" => ServerKind::MinIO,
        "NginxProxyManager" => ServerKind::NginxProxyManager,

        // System services
        "OpenSSH" => ServerKind::OpenSSH,
        "SMB" => ServerKind::SMB,
        "DNS" => ServerKind::DNS,
        "DHCP" => ServerKind::DHCP,
        "FTP" => ServerKind::FTP,
        "SMTP" => ServerKind::SMTP,
        "RDP" => ServerKind::RDP,
        "VNC" => ServerKind::VNC,
        "WinRM" => ServerKind::WinRM,
        "PrintSpooler" => ServerKind::PrintSpooler,
        "HttpSys" => ServerKind::HttpSys,

        // Web frameworks
        "Express" => ServerKind::Express,
        "Fastify" => ServerKind::Fastify,
        "Koa" => ServerKind::Koa,
        "NestJS" => ServerKind::NestJS,
        "Hapi" => ServerKind::Hapi,
        "Nuxt" => ServerKind::Nuxt,
        "AdonisJS" => ServerKind::AdonisJS,
        "Tornado" => ServerKind::Tornado,
        "Sanic" => ServerKind::Sanic,
        "Starlette" => ServerKind::Starlette,
        "Bottle" => ServerKind::Bottle,
        "CherryPy" => ServerKind::CherryPy,
        "Laravel" => ServerKind::Laravel,
        "Symfony" => ServerKind::Symfony,
        "WordPress" => ServerKind::WordPress,
        "Drupal" => ServerKind::Drupal,
        "Micronaut" => ServerKind::Micronaut,
        "Quarkus" => ServerKind::Quarkus,
        "Gin" => ServerKind::Gin,
        "Echo" => ServerKind::Echo,
        "Fiber" => ServerKind::Fiber,
        "Ghost" => ServerKind::Ghost,
        "Strapi" => ServerKind::Strapi,

        // Additional web servers/proxies
        "Jetty" => ServerKind::Jetty,
        "HAProxy" => ServerKind::HAProxy,
        "Varnish" => ServerKind::Varnish,
        "WildFly" => ServerKind::WildFly,
        "Plex" => ServerKind::Plex,
        "Jellyfin" => ServerKind::Jellyfin,

        // Additional databases
        "MSSQL" => ServerKind::MSSQL,
        "CouchDB" => ServerKind::CouchDB,
        "Neo4j" => ServerKind::Neo4j,
        "InfluxDB" => ServerKind::InfluxDB,
        "Cassandra" => ServerKind::Cassandra,
        "Solr" => ServerKind::Solr,
        "MeiliSearch" => ServerKind::MeiliSearch,
        "Typesense" => ServerKind::Typesense,
        "ScyllaDB" => ServerKind::ScyllaDB,
        "TiDB" => ServerKind::TiDB,
        "YugabyteDB" => ServerKind::YugabyteDB,
        "RethinkDB" => ServerKind::RethinkDB,
        "ArangoDB" => ServerKind::ArangoDB,
        "OrientDB" => ServerKind::OrientDB,
        "DGraph" => ServerKind::DGraph,
        "TimescaleDB" => ServerKind::TimescaleDB,
        "QuestDB" => ServerKind::QuestDB,
        "DuckDB" => ServerKind::DuckDB,
        "Firebird" => ServerKind::Firebird,
        "Vitess" => ServerKind::Vitess,
        "ProxySQL" => ServerKind::ProxySQL,
        "MaxScale" => ServerKind::MaxScale,
        "PgBouncer" => ServerKind::PgBouncer,
        "Pgpool" => ServerKind::Pgpool,
        "OracleDB" => ServerKind::OracleDB,
        "DB2" => ServerKind::DB2,

        // Additional dev tools
        "Jupyter" => ServerKind::Jupyter,
        "PgAdmin" => ServerKind::PgAdmin,
        "Swagger" => ServerKind::Swagger,
        "Parcel" => ServerKind::Parcel,
        "Snowpack" => ServerKind::Snowpack,
        "Esbuild" => ServerKind::Esbuild,
        "BrowserSync" => ServerKind::BrowserSync,
        "LiveReload" => ServerKind::LiveReload,
        "JupyterHub" => ServerKind::JupyterHub,
        "RStudioServer" => ServerKind::RStudioServer,
        "CodeServer" => ServerKind::CodeServer,
        "Ngrok" => ServerKind::Ngrok,
        "Cypress" => ServerKind::Cypress,
        "Playwright" => ServerKind::Playwright,
        "SeleniumGrid" => ServerKind::SeleniumGrid,

        // Additional infrastructure
        "Envoy" => ServerKind::Envoy,
        "Jaeger" => ServerKind::Jaeger,
        "Zipkin" => ServerKind::Zipkin,
        "Keycloak" => ServerKind::Keycloak,
        "Kong" => ServerKind::Kong,

        // Additional system
        "Postfix" => ServerKind::Postfix,
        "Dovecot" => ServerKind::Dovecot,
        "Sendmail" => ServerKind::Sendmail,
        "Exim" => ServerKind::Exim,
        "CyrusIMAP" => ServerKind::CyrusIMAP,
        "HMailServer" => ServerKind::HMailServer,
        "Zimbra" => ServerKind::Zimbra,
        "Haraka" => ServerKind::Haraka,

        // Message brokers (additional)
        "ActiveMQ" => ServerKind::ActiveMQ,
        "Pulsar" => ServerKind::Pulsar,
        "RocketMQ" => ServerKind::RocketMQ,
        "NSQ" => ServerKind::NSQ,
        "Beanstalkd" => ServerKind::Beanstalkd,
        "HiveMQ" => ServerKind::HiveMQ,
        "EMQX" => ServerKind::EMQX,
        "VerneMQ" => ServerKind::VerneMQ,

        // Additional web servers
        "OpenResty" => ServerKind::OpenResty,
        "Tengine" => ServerKind::Tengine,
        "H2O" => ServerKind::H2O,
        "Cherokee" => ServerKind::Cherokee,
        "Mongoose" => ServerKind::Mongoose,
        "Squid" => ServerKind::Squid,
        "Privoxy" => ServerKind::Privoxy,
        "Pound" => ServerKind::Pound,

        // CI/CD
        "TeamCity" => ServerKind::TeamCity,
        "Bamboo" => ServerKind::Bamboo,
        "DroneCI" => ServerKind::DroneCI,
        "GoCD" => ServerKind::GoCD,
        "ArgoCD" => ServerKind::ArgoCD,
        "Tekton" => ServerKind::Tekton,
        "BuildkiteAgent" => ServerKind::BuildkiteAgent,
        "WoodpeckerCI" => ServerKind::WoodpeckerCI,
        "Spinnaker" => ServerKind::Spinnaker,
        "Harbor" => ServerKind::Harbor,
        "NexusRepo" => ServerKind::NexusRepo,
        "Artifactory" => ServerKind::Artifactory,
        "Verdaccio" => ServerKind::Verdaccio,
        "Gitea" => ServerKind::Gitea,
        "Gogs" => ServerKind::Gogs,
        "Forgejo" => ServerKind::Forgejo,
        "Concourse" => ServerKind::Concourse,

        // Monitoring
        "Loki" => ServerKind::Loki,
        "Tempo" => ServerKind::Tempo,
        "AlertManager" | "Alertmanager" => ServerKind::AlertManager,

        // VPN & Network
        "OpenVPN" => ServerKind::OpenVPN,
        "WireGuard" => ServerKind::WireGuard,
        "StrongSwan" => ServerKind::StrongSwan,
        "Shadowsocks" => ServerKind::Shadowsocks,
        "V2Ray" => ServerKind::V2Ray,
        "Tailscale" => ServerKind::Tailscale,
        "ZeroTier" => ServerKind::ZeroTier,
        "Headscale" => ServerKind::Headscale,

        // Windows services
        "FileZillaServer" => ServerKind::FileZillaServer,
        "TightVNC" => ServerKind::TightVNC,
        "UltraVNC" => ServerKind::UltraVNC,
        "RealVNC" => ServerKind::RealVNC,
        "Syncthing" => ServerKind::Syncthing,
        "ResilioSync" => ServerKind::ResilioSync,
        "EverythingSearch" => ServerKind::EverythingSearch,
        "WAMP" => ServerKind::WAMP,
        "XAMPP" => ServerKind::XAMPP,
        "Laragon" => ServerKind::Laragon,

        // Misc
        "AndroidAdb" => ServerKind::AndroidAdb,
        "Bonjour" => ServerKind::Bonjour,
        "NordVPN" => ServerKind::NordVPN,
        "AppleMobileDevice" => ServerKind::AppleMobileDevice,
        "IntelSUR" => ServerKind::IntelSUR,
        "HyperVManager" => ServerKind::HyperVManager,

        // Windows svchost services
        "RpcEndpointMapper" => ServerKind::RpcEndpointMapper,
        "SSDP" => ServerKind::SSDP,
        "IPsec" => ServerKind::IPsec,
        "LLMNR" => ServerKind::LLMNR,
        "CDPSvc" => ServerKind::CDPSvc,
        "QWAVE" => ServerKind::QWAVE,
        "FDResPub" => ServerKind::FDResPub,
        "IpHelper" => ServerKind::IpHelper,
        "WindowsEventLog" => ServerKind::WindowsEventLog,
        "TaskScheduler" => ServerKind::TaskScheduler,
        "InternetConnectionSharing" => ServerKind::InternetConnectionSharing,

        // Windows system processes
        "SimpleTcpServices" => ServerKind::SimpleTcpServices,
        "LocalSecurityAuthority" => ServerKind::LocalSecurityAuthority,
        "ServiceControlManager" => ServerKind::ServiceControlManager,
        "WindowsInitProcess" => ServerKind::WindowsInitProcess,
        "DeviceAssociationService" => ServerKind::DeviceAssociationService,
        "WindowsMultiPointServer" => ServerKind::WindowsMultiPointServer,
        "WindowsExplorer" => ServerKind::WindowsExplorer,

        // Desktop / vendor apps
        "AsusGlideX" => ServerKind::AsusGlideX,
        "AsusSoftwareManager" => ServerKind::AsusSoftwareManager,
        "AdGuardService" => ServerKind::AdGuardService,
        "ChatGPTDesktop" => ServerKind::ChatGPTDesktop,
        "ClaudeDesktop" => ServerKind::ClaudeDesktop,
        "VSCode" => ServerKind::VSCode,
        "Psmux" => ServerKind::Psmux,
        "ChromeMdns" => ServerKind::ChromeMdns,

        // Generic / Other
        "CustomHttp" => ServerKind::CustomHttp,
        "GenericTcp" => ServerKind::GenericTcp,
        "GenericUdp" => ServerKind::GenericUdp,
        "Unknown" => ServerKind::Unknown,

        _ => {
            eprintln!("fingerprints.json: unknown kind {:?}, skipping", s);
            return None;
        }
    })
}
