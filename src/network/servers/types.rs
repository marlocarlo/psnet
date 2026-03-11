//! Types for the Servers (local service detection) module.

use std::net::IpAddr;

use chrono::NaiveTime;

/// What kind of server technology is running.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServerKind {
    // -- Web servers --
    Nginx,
    Apache,
    IIS,
    Caddy,
    LiteSpeed,
    Traefik,

    // -- Application runtimes --
    NodeJs,
    Deno,
    Bun,
    Python,
    Django,
    Flask,
    FastAPI,
    Uvicorn,
    Gunicorn,
    Ruby,
    Rails,
    PhpBuiltIn,
    JavaSpringBoot,
    JavaTomcat,
    DotNetKestrel,
    GoHttp,
    RustActix,
    RustAxum,

    // -- Databases --
    PostgreSQL,
    MySQL,
    MariaDB,
    MongoDB,
    Redis,
    SQLite,
    Memcached,
    Elasticsearch,
    ClickHouse,
    CockroachDB,

    // -- Message brokers --
    RabbitMQ,
    Kafka,
    NATS,
    Mosquitto,

    // -- Dev tools --
    ViteDevServer,
    WebpackDevServer,
    NextJs,
    Remix,
    CreateReactApp,
    AngularCli,
    VueCli,
    SvelteKit,
    Astro,
    Hugo,
    Gatsby,
    Storybook,

    // -- Infrastructure --
    Docker,
    Kubernetes,
    Prometheus,
    Grafana,
    Jenkins,
    GitLabRunner,
    Consul,
    Vault,
    MinIO,
    NginxProxyManager,

    // -- System services --
    OpenSSH,
    SMB,
    DNS,
    DHCP,
    FTP,
    SMTP,
    RDP,
    VNC,
    WinRM,
    PrintSpooler,

    // -- Web frameworks --
    Express,
    Fastify,
    Koa,
    NestJS,
    Hapi,
    Nuxt,
    AdonisJS,
    Tornado,
    Sanic,
    Starlette,
    Bottle,
    CherryPy,
    Laravel,
    Symfony,
    WordPress,
    Drupal,
    Micronaut,
    Quarkus,
    Gin,
    Echo,
    Fiber,
    Ghost,
    Strapi,

    // -- Additional web servers / proxies --
    Jetty,
    HAProxy,
    Varnish,

    // -- Additional app runtimes --
    WildFly,
    Plex,
    Jellyfin,

    // -- Additional databases --
    MSSQL,
    CouchDB,
    Neo4j,
    InfluxDB,
    Cassandra,
    Solr,
    MeiliSearch,
    Typesense,

    // -- Additional dev tools --
    Jupyter,
    PgAdmin,
    Swagger,

    // -- Additional infrastructure --
    Envoy,
    Jaeger,
    Zipkin,
    Keycloak,
    Kong,

    // -- Additional system services --
    Postfix,
    Dovecot,

    // -- Additional databases --
    ScyllaDB,
    TiDB,
    YugabyteDB,
    RethinkDB,
    ArangoDB,
    OrientDB,
    DGraph,
    TimescaleDB,
    QuestDB,
    DuckDB,
    Firebird,
    Vitess,
    ProxySQL,
    MaxScale,
    PgBouncer,
    Pgpool,
    OracleDB,
    DB2,

    // -- Additional message brokers --
    ActiveMQ,
    Pulsar,
    RocketMQ,
    NSQ,
    Beanstalkd,
    HiveMQ,
    EMQX,
    VerneMQ,

    // -- Additional web servers --
    OpenResty,
    Tengine,
    H2O,
    Cherokee,
    Mongoose,
    Squid,
    Privoxy,
    Pound,

    // -- Dev tools (additional) --
    Parcel,
    Snowpack,
    Esbuild,
    BrowserSync,
    LiveReload,
    JupyterHub,
    RStudioServer,
    CodeServer,
    Ngrok,
    Cypress,
    Playwright,
    SeleniumGrid,

    // -- CI/CD & DevOps --
    TeamCity,
    Bamboo,
    DroneCI,
    GoCD,
    ArgoCD,
    Tekton,
    BuildkiteAgent,
    WoodpeckerCI,
    Spinnaker,
    Harbor,
    NexusRepo,
    Artifactory,
    Verdaccio,
    Gitea,
    Gogs,
    Forgejo,
    Concourse,

    // -- Monitoring & Observability --
    Kibana,
    Logstash,
    Fluentd,
    FluentBit,
    Tempo,
    Loki,
    AlertManager,
    Nagios,
    Zabbix,
    Icinga,
    Graylog,
    Seq,
    Vector,
    Telegraf,
    Netdata,
    UptimeKuma,

    // -- Container & Orchestration --
    Containerd,
    Etcd,
    CoreDNS,
    Istio,
    Linkerd,
    Nomad,
    Portainer,
    Rancher,
    K3s,

    // -- Game servers --
    Minecraft,
    Factorio,
    Terraria,
    Valheim,
    ArkServer,
    RustGame,
    CounterStrike,
    TeamFortress2,
    GarrysMod,
    SourceEngine,

    // -- Media servers --
    Emby,
    Subsonic,
    Airsonic,
    Navidrome,
    MiniDLNA,
    Icecast,
    SHOUTcast,
    Mumble,
    TeamSpeak,

    // -- Home automation & IoT --
    HomeAssistant,
    OpenHAB,
    Domoticz,
    NodeRED,
    PiHole,
    AdGuardHome,
    Homebridge,

    // -- VPN & Network --
    OpenVPN,
    WireGuard,
    StrongSwan,
    Shadowsocks,
    V2Ray,
    Tailscale,
    ZeroTier,
    Headscale,

    // -- Mail servers (additional) --
    Sendmail,
    Exim,
    CyrusIMAP,
    HMailServer,
    Zimbra,
    Haraka,

    // -- Windows services (additional) --
    FileZillaServer,
    TightVNC,
    UltraVNC,
    RealVNC,
    Syncthing,
    ResilioSync,
    EverythingSearch,
    WAMP,
    XAMPP,
    Laragon,

    // -- Misc services --
    AndroidAdb,
    Bonjour,
    NordVPN,
    AppleMobileDevice,
    IntelSUR,
    HyperVManager,

    // -- Windows system services (svchost-hosted) --
    RpcEndpointMapper,
    SSDP,
    IPsec,
    LLMNR,
    CDPSvc,
    QWAVE,
    FDResPub,
    IpHelper,
    WindowsEventLog,
    TaskScheduler,
    InternetConnectionSharing,

    // -- Other / Unknown --
    CustomHttp,
    GenericTcp,
    GenericUdp,
    Unknown,
}

impl ServerKind {
    /// Human-readable display name.
    pub fn label(&self) -> &str {
        match self {
            Self::Nginx => "Nginx",
            Self::Apache => "Apache HTTP Server",
            Self::IIS => "IIS",
            Self::Caddy => "Caddy",
            Self::LiteSpeed => "LiteSpeed",
            Self::Traefik => "Traefik",

            Self::NodeJs => "Node.js",
            Self::Deno => "Deno",
            Self::Bun => "Bun",
            Self::Python => "Python HTTP",
            Self::Django => "Django",
            Self::Flask => "Flask",
            Self::FastAPI => "FastAPI",
            Self::Uvicorn => "Uvicorn",
            Self::Gunicorn => "Gunicorn",
            Self::Ruby => "Ruby (WEBrick/Puma)",
            Self::Rails => "Ruby on Rails",
            Self::PhpBuiltIn => "PHP Built-in Server",
            Self::JavaSpringBoot => "Spring Boot",
            Self::JavaTomcat => "Apache Tomcat",
            Self::DotNetKestrel => ".NET Kestrel",
            Self::GoHttp => "Go net/http",
            Self::RustActix => "Actix Web",
            Self::RustAxum => "Axum",

            Self::PostgreSQL => "PostgreSQL",
            Self::MySQL => "MySQL",
            Self::MariaDB => "MariaDB",
            Self::MongoDB => "MongoDB",
            Self::Redis => "Redis",
            Self::SQLite => "SQLite",
            Self::Memcached => "Memcached",
            Self::Elasticsearch => "Elasticsearch",
            Self::ClickHouse => "ClickHouse",
            Self::CockroachDB => "CockroachDB",

            Self::RabbitMQ => "RabbitMQ",
            Self::Kafka => "Apache Kafka",
            Self::NATS => "NATS",
            Self::Mosquitto => "Mosquitto (MQTT)",

            Self::ViteDevServer => "Vite Dev Server",
            Self::WebpackDevServer => "Webpack Dev Server",
            Self::NextJs => "Next.js",
            Self::Remix => "Remix",
            Self::CreateReactApp => "Create React App",
            Self::AngularCli => "Angular CLI",
            Self::VueCli => "Vue CLI",
            Self::SvelteKit => "SvelteKit",
            Self::Astro => "Astro",
            Self::Hugo => "Hugo",
            Self::Gatsby => "Gatsby",
            Self::Storybook => "Storybook",

            Self::Docker => "Docker",
            Self::Kubernetes => "Kubernetes",
            Self::Prometheus => "Prometheus",
            Self::Grafana => "Grafana",
            Self::Jenkins => "Jenkins",
            Self::GitLabRunner => "GitLab Runner",
            Self::Consul => "Consul",
            Self::Vault => "HashiCorp Vault",
            Self::MinIO => "MinIO",
            Self::NginxProxyManager => "Nginx Proxy Manager",

            Self::OpenSSH => "OpenSSH",
            Self::SMB => "SMB/CIFS",
            Self::DNS => "DNS Server",
            Self::DHCP => "DHCP Server",
            Self::FTP => "FTP Server",
            Self::SMTP => "SMTP Server",
            Self::RDP => "Remote Desktop",
            Self::VNC => "VNC Server",
            Self::WinRM => "WinRM",
            Self::PrintSpooler => "Print Spooler",

            Self::Express => "Express.js",
            Self::Fastify => "Fastify",
            Self::Koa => "Koa",
            Self::NestJS => "NestJS",
            Self::Hapi => "Hapi",
            Self::Nuxt => "Nuxt.js",
            Self::AdonisJS => "AdonisJS",
            Self::Tornado => "Tornado",
            Self::Sanic => "Sanic",
            Self::Starlette => "Starlette",
            Self::Bottle => "Bottle",
            Self::CherryPy => "CherryPy",
            Self::Laravel => "Laravel",
            Self::Symfony => "Symfony",
            Self::WordPress => "WordPress",
            Self::Drupal => "Drupal",
            Self::Micronaut => "Micronaut",
            Self::Quarkus => "Quarkus",
            Self::Gin => "Gin",
            Self::Echo => "Echo",
            Self::Fiber => "Fiber",
            Self::Ghost => "Ghost",
            Self::Strapi => "Strapi",
            Self::Jetty => "Eclipse Jetty",
            Self::HAProxy => "HAProxy",
            Self::Varnish => "Varnish Cache",
            Self::WildFly => "WildFly",
            Self::Plex => "Plex Media Server",
            Self::Jellyfin => "Jellyfin",
            Self::MSSQL => "Microsoft SQL Server",
            Self::CouchDB => "CouchDB",
            Self::Neo4j => "Neo4j",
            Self::InfluxDB => "InfluxDB",
            Self::Cassandra => "Cassandra",
            Self::Solr => "Apache Solr",
            Self::MeiliSearch => "Meilisearch",
            Self::Typesense => "Typesense",
            Self::Jupyter => "Jupyter Notebook",
            Self::PgAdmin => "pgAdmin",
            Self::Swagger => "Swagger UI",
            Self::Envoy => "Envoy Proxy",
            Self::Jaeger => "Jaeger",
            Self::Zipkin => "Zipkin",
            Self::Keycloak => "Keycloak",
            Self::Kong => "Kong Gateway",
            Self::Postfix => "Postfix",
            Self::Dovecot => "Dovecot",

            // Additional databases
            Self::ScyllaDB => "ScyllaDB",
            Self::TiDB => "TiDB",
            Self::YugabyteDB => "YugabyteDB",
            Self::RethinkDB => "RethinkDB",
            Self::ArangoDB => "ArangoDB",
            Self::OrientDB => "OrientDB",
            Self::DGraph => "Dgraph",
            Self::TimescaleDB => "TimescaleDB",
            Self::QuestDB => "QuestDB",
            Self::DuckDB => "DuckDB",
            Self::Firebird => "Firebird",
            Self::Vitess => "Vitess",
            Self::ProxySQL => "ProxySQL",
            Self::MaxScale => "MaxScale",
            Self::PgBouncer => "PgBouncer",
            Self::Pgpool => "Pgpool-II",
            Self::OracleDB => "Oracle Database",
            Self::DB2 => "IBM DB2",

            // Additional message brokers
            Self::ActiveMQ => "ActiveMQ",
            Self::Pulsar => "Apache Pulsar",
            Self::RocketMQ => "Apache RocketMQ",
            Self::NSQ => "NSQ",
            Self::Beanstalkd => "Beanstalkd",
            Self::HiveMQ => "HiveMQ",
            Self::EMQX => "EMQ X",
            Self::VerneMQ => "VerneMQ",

            // Additional web servers
            Self::OpenResty => "OpenResty",
            Self::Tengine => "Tengine",
            Self::H2O => "H2O",
            Self::Cherokee => "Cherokee",
            Self::Mongoose => "Mongoose",
            Self::Squid => "Squid Proxy",
            Self::Privoxy => "Privoxy",
            Self::Pound => "Pound",

            // Dev tools (additional)
            Self::Parcel => "Parcel",
            Self::Snowpack => "Snowpack",
            Self::Esbuild => "esbuild",
            Self::BrowserSync => "Browsersync",
            Self::LiveReload => "LiveReload",
            Self::JupyterHub => "JupyterHub",
            Self::RStudioServer => "RStudio Server",
            Self::CodeServer => "code-server",
            Self::Ngrok => "ngrok",
            Self::Cypress => "Cypress",
            Self::Playwright => "Playwright",
            Self::SeleniumGrid => "Selenium Grid",

            // CI/CD & DevOps
            Self::TeamCity => "TeamCity",
            Self::Bamboo => "Bamboo",
            Self::DroneCI => "Drone CI",
            Self::GoCD => "GoCD",
            Self::ArgoCD => "Argo CD",
            Self::Tekton => "Tekton",
            Self::BuildkiteAgent => "Buildkite Agent",
            Self::WoodpeckerCI => "Woodpecker CI",
            Self::Spinnaker => "Spinnaker",
            Self::Harbor => "Harbor",
            Self::NexusRepo => "Nexus Repository",
            Self::Artifactory => "JFrog Artifactory",
            Self::Verdaccio => "Verdaccio",
            Self::Gitea => "Gitea",
            Self::Gogs => "Gogs",
            Self::Forgejo => "Forgejo",
            Self::Concourse => "Concourse CI",

            // Monitoring & Observability
            Self::Kibana => "Kibana",
            Self::Logstash => "Logstash",
            Self::Fluentd => "Fluentd",
            Self::FluentBit => "Fluent Bit",
            Self::Tempo => "Grafana Tempo",
            Self::Loki => "Grafana Loki",
            Self::AlertManager => "Alertmanager",
            Self::Nagios => "Nagios",
            Self::Zabbix => "Zabbix",
            Self::Icinga => "Icinga",
            Self::Graylog => "Graylog",
            Self::Seq => "Seq",
            Self::Vector => "Vector",
            Self::Telegraf => "Telegraf",
            Self::Netdata => "Netdata",
            Self::UptimeKuma => "Uptime Kuma",

            // Container & Orchestration
            Self::Containerd => "containerd",
            Self::Etcd => "etcd",
            Self::CoreDNS => "CoreDNS",
            Self::Istio => "Istio",
            Self::Linkerd => "Linkerd",
            Self::Nomad => "HashiCorp Nomad",
            Self::Portainer => "Portainer",
            Self::Rancher => "Rancher",
            Self::K3s => "K3s",

            // Game servers
            Self::Minecraft => "Minecraft Server",
            Self::Factorio => "Factorio Server",
            Self::Terraria => "Terraria Server",
            Self::Valheim => "Valheim Server",
            Self::ArkServer => "ARK Server",
            Self::RustGame => "Rust (Game) Server",
            Self::CounterStrike => "Counter-Strike Server",
            Self::TeamFortress2 => "Team Fortress 2 Server",
            Self::GarrysMod => "Garry's Mod Server",
            Self::SourceEngine => "Source Engine Server",

            // Media servers
            Self::Emby => "Emby",
            Self::Subsonic => "Subsonic",
            Self::Airsonic => "Airsonic",
            Self::Navidrome => "Navidrome",
            Self::MiniDLNA => "MiniDLNA",
            Self::Icecast => "Icecast",
            Self::SHOUTcast => "SHOUTcast",
            Self::Mumble => "Mumble",
            Self::TeamSpeak => "TeamSpeak",

            // Home automation
            Self::HomeAssistant => "Home Assistant",
            Self::OpenHAB => "OpenHAB",
            Self::Domoticz => "Domoticz",
            Self::NodeRED => "Node-RED",
            Self::PiHole => "Pi-hole",
            Self::AdGuardHome => "AdGuard Home",
            Self::Homebridge => "Homebridge",

            // VPN & Network
            Self::OpenVPN => "OpenVPN",
            Self::WireGuard => "WireGuard",
            Self::StrongSwan => "strongSwan",
            Self::Shadowsocks => "Shadowsocks",
            Self::V2Ray => "V2Ray",
            Self::Tailscale => "Tailscale",
            Self::ZeroTier => "ZeroTier",
            Self::Headscale => "Headscale",

            // Mail servers (additional)
            Self::Sendmail => "Sendmail",
            Self::Exim => "Exim",
            Self::CyrusIMAP => "Cyrus IMAP",
            Self::HMailServer => "hMailServer",
            Self::Zimbra => "Zimbra",
            Self::Haraka => "Haraka",

            // Windows services (additional)
            Self::FileZillaServer => "FileZilla Server",
            Self::TightVNC => "TightVNC",
            Self::UltraVNC => "UltraVNC",
            Self::RealVNC => "RealVNC",
            Self::Syncthing => "Syncthing",
            Self::ResilioSync => "Resilio Sync",
            Self::EverythingSearch => "Everything Search",
            Self::WAMP => "WampServer",
            Self::XAMPP => "XAMPP",
            Self::Laragon => "Laragon",

            Self::AndroidAdb => "Android Debug Bridge",
            Self::Bonjour => "Bonjour (mDNS)",
            Self::NordVPN => "NordVPN Service",
            Self::AppleMobileDevice => "Apple Mobile Device",
            Self::IntelSUR => "Intel SUR",
            Self::HyperVManager => "Hyper-V Manager",

            Self::RpcEndpointMapper => "RPC Endpoint Mapper",
            Self::SSDP => "SSDP (UPnP Discovery)",
            Self::IPsec => "IPsec (IKE)",
            Self::LLMNR => "LLMNR",
            Self::CDPSvc => "Connected Devices Platform",
            Self::QWAVE => "Quality Audio/Video (qWave)",
            Self::FDResPub => "Function Discovery",
            Self::IpHelper => "IP Helper Service",
            Self::WindowsEventLog => "Windows Event Log",
            Self::TaskScheduler => "Task Scheduler",
            Self::InternetConnectionSharing => "Internet Connection Sharing",

            Self::CustomHttp => "HTTP Server (unknown)",
            Self::GenericTcp => "TCP Listener",
            Self::GenericUdp => "UDP Listener",
            Self::Unknown => "Unknown",
        }
    }

    /// Category grouping for UI display.
    pub fn category(&self) -> ServerCategory {
        match self {
            Self::Nginx
            | Self::Apache
            | Self::IIS
            | Self::Caddy
            | Self::LiteSpeed
            | Self::Traefik
            | Self::Jetty
            | Self::HAProxy
            | Self::Varnish
            | Self::OpenResty
            | Self::Tengine
            | Self::H2O
            | Self::Cherokee
            | Self::Mongoose
            | Self::Squid
            | Self::Privoxy
            | Self::Pound => ServerCategory::WebServer,

            Self::NodeJs
            | Self::Deno
            | Self::Bun
            | Self::Python
            | Self::Django
            | Self::Flask
            | Self::FastAPI
            | Self::Uvicorn
            | Self::Gunicorn
            | Self::Ruby
            | Self::Rails
            | Self::PhpBuiltIn
            | Self::JavaSpringBoot
            | Self::JavaTomcat
            | Self::DotNetKestrel
            | Self::GoHttp
            | Self::RustActix
            | Self::RustAxum
            | Self::WildFly
            | Self::Plex
            | Self::Jellyfin
            | Self::Emby
            | Self::Subsonic
            | Self::Airsonic
            | Self::Navidrome
            | Self::MiniDLNA
            | Self::Icecast
            | Self::SHOUTcast
            | Self::Mumble
            | Self::TeamSpeak
            | Self::Minecraft
            | Self::Factorio
            | Self::Terraria
            | Self::Valheim
            | Self::ArkServer
            | Self::RustGame
            | Self::CounterStrike
            | Self::TeamFortress2
            | Self::GarrysMod
            | Self::SourceEngine
            | Self::HomeAssistant
            | Self::OpenHAB
            | Self::Domoticz
            | Self::NodeRED
            | Self::Homebridge
            | Self::WAMP
            | Self::XAMPP
            | Self::Laragon => ServerCategory::AppRuntime,

            Self::Express
            | Self::Fastify
            | Self::Koa
            | Self::NestJS
            | Self::Hapi
            | Self::AdonisJS
            | Self::Tornado
            | Self::Sanic
            | Self::Starlette
            | Self::Bottle
            | Self::CherryPy
            | Self::Laravel
            | Self::Symfony
            | Self::WordPress
            | Self::Drupal
            | Self::Micronaut
            | Self::Quarkus
            | Self::Gin
            | Self::Echo
            | Self::Fiber
            | Self::Ghost
            | Self::Strapi => ServerCategory::WebFramework,

            Self::PostgreSQL
            | Self::MySQL
            | Self::MariaDB
            | Self::MongoDB
            | Self::Redis
            | Self::SQLite
            | Self::Memcached
            | Self::Elasticsearch
            | Self::ClickHouse
            | Self::CockroachDB
            | Self::MSSQL
            | Self::CouchDB
            | Self::Neo4j
            | Self::InfluxDB
            | Self::Cassandra
            | Self::Solr
            | Self::MeiliSearch
            | Self::Typesense
            | Self::ScyllaDB
            | Self::TiDB
            | Self::YugabyteDB
            | Self::RethinkDB
            | Self::ArangoDB
            | Self::OrientDB
            | Self::DGraph
            | Self::TimescaleDB
            | Self::QuestDB
            | Self::DuckDB
            | Self::Firebird
            | Self::Vitess
            | Self::ProxySQL
            | Self::MaxScale
            | Self::PgBouncer
            | Self::Pgpool
            | Self::OracleDB
            | Self::DB2 => ServerCategory::Database,

            Self::RabbitMQ
            | Self::Kafka
            | Self::NATS
            | Self::Mosquitto
            | Self::ActiveMQ
            | Self::Pulsar
            | Self::RocketMQ
            | Self::NSQ
            | Self::Beanstalkd
            | Self::HiveMQ
            | Self::EMQX
            | Self::VerneMQ => ServerCategory::MessageBroker,

            Self::ViteDevServer
            | Self::WebpackDevServer
            | Self::NextJs
            | Self::Nuxt
            | Self::Remix
            | Self::CreateReactApp
            | Self::AngularCli
            | Self::VueCli
            | Self::SvelteKit
            | Self::Astro
            | Self::Hugo
            | Self::Gatsby
            | Self::Storybook
            | Self::Jupyter
            | Self::PgAdmin
            | Self::Swagger
            | Self::Parcel
            | Self::Snowpack
            | Self::Esbuild
            | Self::BrowserSync
            | Self::LiveReload
            | Self::JupyterHub
            | Self::RStudioServer
            | Self::CodeServer
            | Self::Ngrok
            | Self::Cypress
            | Self::Playwright
            | Self::SeleniumGrid => ServerCategory::DevTool,

            Self::Docker
            | Self::Kubernetes
            | Self::Prometheus
            | Self::Grafana
            | Self::Jenkins
            | Self::GitLabRunner
            | Self::Consul
            | Self::Vault
            | Self::MinIO
            | Self::NginxProxyManager
            | Self::Envoy
            | Self::Jaeger
            | Self::Zipkin
            | Self::Keycloak
            | Self::Kong
            | Self::TeamCity
            | Self::Bamboo
            | Self::DroneCI
            | Self::GoCD
            | Self::ArgoCD
            | Self::Tekton
            | Self::BuildkiteAgent
            | Self::WoodpeckerCI
            | Self::Spinnaker
            | Self::Harbor
            | Self::NexusRepo
            | Self::Artifactory
            | Self::Verdaccio
            | Self::Gitea
            | Self::Gogs
            | Self::Forgejo
            | Self::Concourse
            | Self::Kibana
            | Self::Logstash
            | Self::Fluentd
            | Self::FluentBit
            | Self::Tempo
            | Self::Loki
            | Self::AlertManager
            | Self::Nagios
            | Self::Zabbix
            | Self::Icinga
            | Self::Graylog
            | Self::Seq
            | Self::Vector
            | Self::Telegraf
            | Self::Netdata
            | Self::UptimeKuma
            | Self::Containerd
            | Self::Etcd
            | Self::CoreDNS
            | Self::Istio
            | Self::Linkerd
            | Self::Nomad
            | Self::Portainer
            | Self::Rancher
            | Self::K3s => ServerCategory::Infrastructure,

            Self::OpenSSH
            | Self::SMB
            | Self::DNS
            | Self::DHCP
            | Self::FTP
            | Self::SMTP
            | Self::RDP
            | Self::VNC
            | Self::WinRM
            | Self::PrintSpooler
            | Self::Postfix
            | Self::Dovecot
            | Self::Sendmail
            | Self::Exim
            | Self::CyrusIMAP
            | Self::HMailServer
            | Self::Zimbra
            | Self::Haraka
            | Self::OpenVPN
            | Self::WireGuard
            | Self::StrongSwan
            | Self::Shadowsocks
            | Self::V2Ray
            | Self::Tailscale
            | Self::ZeroTier
            | Self::Headscale
            | Self::PiHole
            | Self::AdGuardHome
            | Self::FileZillaServer
            | Self::TightVNC
            | Self::UltraVNC
            | Self::RealVNC
            | Self::Syncthing
            | Self::ResilioSync
            | Self::EverythingSearch
            | Self::AndroidAdb
            | Self::Bonjour
            | Self::NordVPN
            | Self::AppleMobileDevice
            | Self::IntelSUR
            | Self::HyperVManager
            | Self::RpcEndpointMapper
            | Self::SSDP
            | Self::IPsec
            | Self::LLMNR
            | Self::CDPSvc
            | Self::QWAVE
            | Self::FDResPub
            | Self::IpHelper
            | Self::WindowsEventLog
            | Self::TaskScheduler
            | Self::InternetConnectionSharing => ServerCategory::SystemService,

            Self::CustomHttp
            | Self::GenericTcp
            | Self::GenericUdp
            | Self::Unknown => ServerCategory::Other,
        }
    }

    /// Color for UI rendering (RGB tuple). Distinct per category.
    pub fn color(&self) -> (u8, u8, u8) {
        self.category().color()
    }

    /// Icon/prefix for the kind. Uses simple ASCII/unicode chars for terminal compatibility.
    pub fn icon(&self) -> &str {
        match self {
            // Web servers
            Self::Nginx | Self::Apache | Self::IIS | Self::Caddy
            | Self::LiteSpeed | Self::Traefik => "W",

            // App runtimes
            Self::NodeJs | Self::Deno | Self::Bun => "js",
            Self::Python | Self::Django | Self::Flask
            | Self::FastAPI | Self::Uvicorn | Self::Gunicorn => "py",
            Self::Ruby | Self::Rails => "rb",
            Self::PhpBuiltIn => "ph",
            Self::JavaSpringBoot | Self::JavaTomcat => "jv",
            Self::DotNetKestrel => "cs",
            Self::GoHttp => "go",
            Self::RustActix | Self::RustAxum => "rs",

            // Databases
            Self::PostgreSQL => "pg",
            Self::MySQL | Self::MariaDB => "my",
            Self::MongoDB => "mg",
            Self::Redis => "rd",
            Self::SQLite => "sq",
            Self::Memcached => "mc",
            Self::Elasticsearch => "es",
            Self::ClickHouse => "ch",
            Self::CockroachDB => "cr",

            // Message brokers
            Self::RabbitMQ => "mq",
            Self::Kafka => "kf",
            Self::NATS => "nt",
            Self::Mosquitto => "mt",

            // Dev tools
            Self::ViteDevServer => "vi",
            Self::WebpackDevServer => "wp",
            Self::NextJs => "nx",
            Self::Remix => "rx",
            Self::CreateReactApp => "ra",
            Self::AngularCli => "ng",
            Self::VueCli => "vu",
            Self::SvelteKit => "sv",
            Self::Astro => "as",
            Self::Hugo => "hu",
            Self::Gatsby => "gb",
            Self::Storybook => "sb",

            // Infrastructure
            Self::Docker => "dk",
            Self::Kubernetes => "k8",
            Self::Prometheus => "pm",
            Self::Grafana => "gf",
            Self::Jenkins => "jk",
            Self::GitLabRunner => "gl",
            Self::Consul => "cl",
            Self::Vault => "vt",
            Self::MinIO => "mn",
            Self::NginxProxyManager => "np",

            // System services
            Self::OpenSSH => "ss",
            Self::SMB => "sm",
            Self::DNS => "dn",
            Self::DHCP => "dh",
            Self::FTP => "ft",
            Self::SMTP => "ml",
            Self::RDP => "dp",
            Self::VNC => "vn",
            Self::WinRM => "wr",
            Self::PrintSpooler => "pr",

            // Web frameworks
            Self::Express => "ex",
            Self::Fastify => "fy",
            Self::Koa => "ko",
            Self::NestJS => "ne",
            Self::Hapi => "hp",
            Self::Nuxt => "nu",
            Self::AdonisJS => "ad",
            Self::Tornado => "tn",
            Self::Sanic => "sn",
            Self::Starlette => "st",
            Self::Bottle => "bt",
            Self::CherryPy => "cp",
            Self::Laravel => "lv",
            Self::Symfony => "sf",
            Self::WordPress => "wp",
            Self::Drupal => "dp",
            Self::Micronaut => "mi",
            Self::Quarkus => "qk",
            Self::Gin => "gi",
            Self::Echo => "ec",
            Self::Fiber => "fb",
            Self::Ghost => "gh",
            Self::Strapi => "sp",

            // Additional web servers / proxies
            Self::Jetty => "jt",
            Self::HAProxy => "ha",
            Self::Varnish => "va",

            // Additional app runtimes
            Self::WildFly => "wf",
            Self::Plex => "px",
            Self::Jellyfin => "jf",

            // Additional databases
            Self::MSSQL => "ms",
            Self::CouchDB => "co",
            Self::Neo4j => "n4",
            Self::InfluxDB => "if",
            Self::Cassandra => "ca",
            Self::Solr => "sl",
            Self::MeiliSearch => "me",
            Self::Typesense => "ts",

            // Additional dev tools
            Self::Jupyter => "ju",
            Self::PgAdmin => "pa",
            Self::Swagger => "sw",

            // Additional infrastructure
            Self::Envoy => "ev",
            Self::Jaeger => "jg",
            Self::Zipkin => "zk",
            Self::Keycloak => "kc",
            Self::Kong => "kg",

            // Additional system services
            Self::Postfix => "pf",
            Self::Dovecot => "dc",

            // Additional databases
            Self::ScyllaDB | Self::TiDB | Self::YugabyteDB => "db",
            Self::RethinkDB | Self::ArangoDB | Self::OrientDB | Self::DGraph => "db",
            Self::TimescaleDB | Self::QuestDB | Self::DuckDB => "db",
            Self::Firebird | Self::OracleDB | Self::DB2 => "db",
            Self::Vitess | Self::ProxySQL | Self::MaxScale | Self::PgBouncer | Self::Pgpool => "px",

            // Additional message brokers
            Self::ActiveMQ | Self::Pulsar | Self::RocketMQ => "mq",
            Self::NSQ | Self::Beanstalkd => "mq",
            Self::HiveMQ | Self::EMQX | Self::VerneMQ => "mt",

            // Additional web servers
            Self::OpenResty | Self::Tengine => "W",
            Self::H2O | Self::Cherokee | Self::Mongoose | Self::Pound => "W",
            Self::Squid | Self::Privoxy => "px",

            // Dev tools (additional)
            Self::Parcel | Self::Snowpack | Self::Esbuild => "bd",
            Self::BrowserSync | Self::LiveReload => "lr",
            Self::JupyterHub => "ju",
            Self::RStudioServer => "R",
            Self::CodeServer => "vs",
            Self::Ngrok => "ng",
            Self::Cypress | Self::Playwright | Self::SeleniumGrid => "te",

            // CI/CD & DevOps
            Self::TeamCity | Self::Bamboo | Self::DroneCI | Self::GoCD => "ci",
            Self::ArgoCD | Self::Tekton | Self::BuildkiteAgent | Self::WoodpeckerCI => "ci",
            Self::Spinnaker | Self::Concourse => "ci",
            Self::Harbor | Self::NexusRepo | Self::Artifactory | Self::Verdaccio => "rg",
            Self::Gitea | Self::Gogs | Self::Forgejo => "gt",

            // Monitoring & Observability
            Self::Kibana => "kb",
            Self::Logstash | Self::Fluentd | Self::FluentBit | Self::Vector => "lg",
            Self::Tempo | Self::Loki | Self::AlertManager => "ob",
            Self::Nagios | Self::Zabbix | Self::Icinga => "mo",
            Self::Graylog | Self::Seq => "lg",
            Self::Telegraf => "tg",
            Self::Netdata | Self::UptimeKuma => "mo",

            // Container & Orchestration
            Self::Containerd => "ct",
            Self::Etcd => "et",
            Self::CoreDNS => "cd",
            Self::Istio | Self::Linkerd => "sm",
            Self::Nomad => "no",
            Self::Portainer | Self::Rancher => "dk",
            Self::K3s => "k3",

            // Game servers
            Self::Minecraft => "mc",
            Self::Factorio | Self::Terraria | Self::Valheim => "gm",
            Self::ArkServer | Self::RustGame => "gm",
            Self::CounterStrike | Self::TeamFortress2 | Self::GarrysMod | Self::SourceEngine => "sr",

            // Media servers
            Self::Emby => "em",
            Self::Subsonic | Self::Airsonic | Self::Navidrome => "mu",
            Self::MiniDLNA => "dl",
            Self::Icecast | Self::SHOUTcast => "ra",
            Self::Mumble | Self::TeamSpeak => "vc",

            // Home automation
            Self::HomeAssistant => "ha",
            Self::OpenHAB | Self::Domoticz => "io",
            Self::NodeRED => "nr",
            Self::PiHole | Self::AdGuardHome => "ad",
            Self::Homebridge => "hb",

            // VPN & Network
            Self::OpenVPN | Self::WireGuard | Self::StrongSwan => "vp",
            Self::Shadowsocks | Self::V2Ray => "px",
            Self::Tailscale | Self::ZeroTier | Self::Headscale => "vp",

            // Mail servers (additional)
            Self::Sendmail | Self::Exim => "ml",
            Self::CyrusIMAP | Self::HMailServer | Self::Zimbra | Self::Haraka => "ml",

            // Windows services (additional)
            Self::FileZillaServer => "ft",
            Self::TightVNC | Self::UltraVNC | Self::RealVNC => "vn",
            Self::Syncthing | Self::ResilioSync => "sy",
            Self::EverythingSearch => "sr",
            Self::WAMP | Self::XAMPP | Self::Laragon => "W",

            Self::AndroidAdb => "ADB",
            Self::Bonjour => "mDNS",
            Self::NordVPN => "NVPN",
            Self::AppleMobileDevice => "AMDS",
            Self::IntelSUR => "ISUR",
            Self::HyperVManager => "HV",

            Self::RpcEndpointMapper => "RPC",
            Self::SSDP => "SSDP",
            Self::IPsec => "IKE",
            Self::LLMNR => "LLMR",
            Self::CDPSvc => "CDP",
            Self::QWAVE => "QW",
            Self::FDResPub => "FD",
            Self::IpHelper => "IPH",
            Self::WindowsEventLog => "EVT",
            Self::TaskScheduler => "TS",
            Self::InternetConnectionSharing => "ICS",

            // Other
            Self::CustomHttp => "h?",
            Self::GenericTcp => "t?",
            Self::GenericUdp => "u?",
            Self::Unknown => "??",
        }
    }

    /// Priority for sorting (lower = shown first).
    pub fn sort_priority(&self) -> u8 {
        match self.category() {
            ServerCategory::DevTool => 0,
            ServerCategory::AppRuntime => 1,
            ServerCategory::WebServer => 1,
            ServerCategory::WebFramework => 1,
            ServerCategory::Database => 2,
            ServerCategory::MessageBroker => 3,
            ServerCategory::Infrastructure => 4,
            ServerCategory::SystemService => 5,
            ServerCategory::Other => 9,
        }
    }

    /// Short description of what the technology is/does.
    pub fn description(&self) -> &str {
        match self {
            Self::Nginx => "High-performance reverse proxy and web server",
            Self::Apache => "World's most widely used open-source web server",
            Self::IIS => "Microsoft's extensible web server for Windows",
            Self::Caddy => "Powerful automatic HTTPS web server in Go",
            Self::LiteSpeed => "High-performance HTTP server with Apache compatibility",
            Self::Traefik => "Cloud-native edge router and reverse proxy",

            Self::NodeJs => "JavaScript runtime built on Chrome's V8 engine",
            Self::Deno => "Secure TypeScript/JavaScript runtime with built-in tools",
            Self::Bun => "Ultra-fast JavaScript runtime, bundler, and package manager",
            Self::Python => "Python's built-in HTTP server for development",
            Self::Django => "High-level Python web framework for rapid development",
            Self::Flask => "Lightweight Python WSGI micro web framework",
            Self::FastAPI => "Modern high-performance Python web framework with async",
            Self::Uvicorn => "Lightning-fast ASGI server for Python async frameworks",
            Self::Gunicorn => "Python WSGI HTTP server for Unix production deploys",
            Self::Ruby => "Ruby's built-in WEBrick or Puma web server",
            Self::Rails => "Full-stack Ruby web framework for convention-driven apps",
            Self::PhpBuiltIn => "PHP's built-in development web server",
            Self::JavaSpringBoot => "Java framework for production-grade Spring applications",
            Self::JavaTomcat => "Apache's Java servlet container and web server",
            Self::DotNetKestrel => "Cross-platform web server for ASP.NET Core",
            Self::GoHttp => "Go standard library HTTP server implementation",
            Self::RustActix => "Powerful Rust web framework with actor system",
            Self::RustAxum => "Ergonomic Rust web framework built on Tokio",

            Self::PostgreSQL => "Advanced open-source relational database system",
            Self::MySQL => "World's most popular open-source relational database",
            Self::MariaDB => "Community-developed fork of MySQL database server",
            Self::MongoDB => "Document-oriented NoSQL database for modern apps",
            Self::Redis => "In-memory data structure store, cache, and broker",
            Self::SQLite => "Self-contained serverless embedded SQL database engine",
            Self::Memcached => "High-performance distributed memory caching system",
            Self::Elasticsearch => "Distributed search and analytics engine for all data",
            Self::ClickHouse => "Fast open-source column-oriented analytics database",
            Self::CockroachDB => "Distributed SQL database for cloud-native applications",

            Self::RabbitMQ => "Open-source message broker implementing AMQP protocol",
            Self::Kafka => "Distributed event streaming platform for high-throughput",
            Self::NATS => "Cloud-native messaging system for microservices",
            Self::Mosquitto => "Lightweight open-source MQTT broker for IoT devices",

            Self::ViteDevServer => "Next-generation frontend build tool with HMR",
            Self::WebpackDevServer => "Development server for Webpack with live reloading",
            Self::NextJs => "React framework for production with SSR and SSG",
            Self::Remix => "Full-stack React framework focused on web standards",
            Self::CreateReactApp => "Official React scaffolding tool with zero configuration",
            Self::AngularCli => "CLI tool for Angular application development",
            Self::VueCli => "Standard tooling for Vue.js project development",
            Self::SvelteKit => "Full-stack framework for building Svelte applications",
            Self::Astro => "Content-focused static site builder with island architecture",
            Self::Hugo => "World's fastest static site generator built in Go",
            Self::Gatsby => "React-based static site generator with GraphQL",
            Self::Storybook => "UI component workshop for frontend development",

            Self::Docker => "Container platform for building and running applications",
            Self::Kubernetes => "Container orchestration platform for automated deployment",
            Self::Prometheus => "Monitoring system and time series database",
            Self::Grafana => "Open-source analytics and interactive visualization platform",
            Self::Jenkins => "Open-source automation server for CI/CD pipelines",
            Self::GitLabRunner => "GitLab's CI/CD pipeline job execution agent",
            Self::Consul => "Service mesh and service discovery by HashiCorp",
            Self::Vault => "Secrets management and data protection by HashiCorp",
            Self::MinIO => "High-performance S3-compatible object storage server",
            Self::NginxProxyManager => "Docker-based Nginx reverse proxy management UI",

            Self::OpenSSH => "Secure remote login and file transfer protocol",
            Self::SMB => "Windows network file sharing protocol service",
            Self::DNS => "Domain Name System resolver and server",
            Self::DHCP => "Dynamic Host Configuration Protocol server",
            Self::FTP => "File Transfer Protocol server for remote file access",
            Self::SMTP => "Simple Mail Transfer Protocol email server",
            Self::RDP => "Microsoft Remote Desktop Protocol service",
            Self::VNC => "Virtual Network Computing remote desktop server",
            Self::WinRM => "Windows Remote Management service for PowerShell",
            Self::PrintSpooler => "Windows print job management background service",

            Self::Express => "Minimal Node.js web framework for APIs and apps",
            Self::Fastify => "High-performance Node.js web framework",
            Self::Koa => "Expressive Node.js middleware framework by Express team",
            Self::NestJS => "Progressive Node.js framework for scalable server apps",
            Self::Hapi => "Rich Node.js framework for building apps and services",
            Self::Nuxt => "Vue.js meta-framework with SSR and static generation",
            Self::AdonisJS => "Full-featured Node.js MVC framework with TypeScript",
            Self::Tornado => "Python async networking library and web framework",
            Self::Sanic => "Async Python web server built for fast responses",
            Self::Starlette => "Lightweight ASGI framework for high-performance Python",
            Self::Bottle => "Simple single-file Python micro web framework",
            Self::CherryPy => "Pythonic object-oriented HTTP framework",
            Self::Laravel => "Elegant PHP framework for modern web artisans",
            Self::Symfony => "Professional PHP framework and reusable components",
            Self::WordPress => "World's most popular content management system",
            Self::Drupal => "Enterprise open-source CMS and digital platform",
            Self::Jetty => "Lightweight embeddable Java HTTP server and servlet container",
            Self::WildFly => "JBoss application server for enterprise Java applications",
            Self::Micronaut => "JVM framework for modular microservices and serverless",
            Self::Quarkus => "Kubernetes-native Java stack for GraalVM and OpenJDK",
            Self::Gin => "High-performance Go HTTP web framework",
            Self::Echo => "High-performance extensible Go web framework",
            Self::Fiber => "Express-inspired Go web framework built on Fasthttp",
            Self::MSSQL => "Enterprise relational database management system",
            Self::CouchDB => "Apache document-oriented NoSQL database with HTTP API",
            Self::Neo4j => "Native graph database for connected data applications",
            Self::InfluxDB => "Purpose-built time series database for metrics and events",
            Self::Cassandra => "Distributed wide-column NoSQL database for high availability",
            Self::Solr => "Enterprise search platform built on Apache Lucene",
            Self::MeiliSearch => "Lightning-fast open-source search engine in Rust",
            Self::Typesense => "Open-source typo-tolerant search engine",
            Self::HAProxy => "Reliable high-performance TCP/HTTP load balancer",
            Self::Varnish => "High-performance HTTP accelerator and reverse proxy",
            Self::Envoy => "Cloud-native high-performance edge/service proxy",
            Self::Jupyter => "Interactive computing environment for data science",
            Self::PgAdmin => "Open-source administration platform for PostgreSQL",
            Self::Swagger => "Interactive REST API documentation and testing tool",
            Self::Jaeger => "Open-source distributed tracing for microservices",
            Self::Zipkin => "Distributed tracing system for latency troubleshooting",
            Self::Ghost => "Professional open-source publishing and blogging platform",
            Self::Strapi => "Open-source headless CMS built with Node.js",
            Self::Keycloak => "Open-source identity and access management by Red Hat",
            Self::Kong => "Cloud-native API gateway and microservices platform",
            Self::Postfix => "High-performance open-source mail transfer agent",
            Self::Dovecot => "Open-source IMAP and POP3 email server",
            Self::Plex => "Personal media streaming and organization server",
            Self::Jellyfin => "Free open-source media streaming server system",

            // Additional databases
            Self::ScyllaDB => "High-performance NoSQL database compatible with Cassandra",
            Self::TiDB => "Distributed SQL database compatible with MySQL protocol",
            Self::YugabyteDB => "Distributed SQL database for cloud-native applications",
            Self::RethinkDB => "Open-source database for real-time web applications",
            Self::ArangoDB => "Native multi-model database for graphs, documents, and search",
            Self::OrientDB => "Multi-model database combining graph and document models",
            Self::DGraph => "Distributed graph database with GraphQL interface",
            Self::TimescaleDB => "Time-series database built on PostgreSQL",
            Self::QuestDB => "High-performance time-series database with SQL support",
            Self::DuckDB => "In-process analytical database with columnar storage",
            Self::Firebird => "Cross-platform relational database with SQL support",
            Self::Vitess => "Database clustering system for horizontal scaling of MySQL",
            Self::ProxySQL => "High-performance MySQL proxy and load balancer",
            Self::MaxScale => "Database proxy for MariaDB and MySQL servers",
            Self::PgBouncer => "Lightweight connection pooler for PostgreSQL",
            Self::Pgpool => "Connection pooling and load balancing for PostgreSQL",
            Self::OracleDB => "Enterprise relational database management system by Oracle",
            Self::DB2 => "Enterprise relational database by IBM",

            // Additional message brokers
            Self::ActiveMQ => "Open-source message broker by Apache Foundation",
            Self::Pulsar => "Distributed pub-sub messaging platform by Apache",
            Self::RocketMQ => "Distributed messaging and streaming platform by Apache",
            Self::NSQ => "Realtime distributed messaging platform in Go",
            Self::Beanstalkd => "Simple fast work queue for background job processing",
            Self::HiveMQ => "Enterprise MQTT broker for IoT messaging",
            Self::EMQX => "Scalable open-source MQTT broker for IoT and M2M",
            Self::VerneMQ => "High-performance distributed MQTT message broker",

            // Additional web servers
            Self::OpenResty => "Nginx-based web platform with Lua scripting",
            Self::Tengine => "Nginx fork by Alibaba with additional features",
            Self::H2O => "Optimized HTTP/1.x, HTTP/2 and HTTP/3 web server",
            Self::Cherokee => "Lightweight high-performance web server",
            Self::Mongoose => "Embedded web server and networking library",
            Self::Squid => "Caching and forwarding HTTP web proxy",
            Self::Privoxy => "Non-caching web proxy with filtering capabilities",
            Self::Pound => "Reverse proxy and load balancer for HTTP/HTTPS",

            // Dev tools (additional)
            Self::Parcel => "Zero-configuration web application bundler",
            Self::Snowpack => "Lightning-fast frontend build tool for modern web",
            Self::Esbuild => "Extremely fast JavaScript and CSS bundler",
            Self::BrowserSync => "Synchronized browser testing and live reload",
            Self::LiveReload => "Browser auto-reload on file changes",
            Self::JupyterHub => "Multi-user server for Jupyter notebooks",
            Self::RStudioServer => "Web-based IDE for R programming",
            Self::CodeServer => "VS Code running in the browser",
            Self::Ngrok => "Secure tunnels to expose local servers publicly",
            Self::Cypress => "End-to-end testing framework for web applications",
            Self::Playwright => "Cross-browser end-to-end testing framework",
            Self::SeleniumGrid => "Distributed test execution for Selenium WebDriver",

            // CI/CD & DevOps
            Self::TeamCity => "CI/CD server by JetBrains for build automation",
            Self::Bamboo => "CI/CD server by Atlassian for build pipelines",
            Self::DroneCI => "Container-native continuous delivery platform",
            Self::GoCD => "Open-source continuous delivery server by ThoughtWorks",
            Self::ArgoCD => "Declarative GitOps continuous delivery for Kubernetes",
            Self::Tekton => "Cloud-native CI/CD framework for Kubernetes",
            Self::BuildkiteAgent => "Build runner agent for Buildkite CI/CD",
            Self::WoodpeckerCI => "Community fork of Drone CI pipeline engine",
            Self::Spinnaker => "Multi-cloud continuous delivery platform by Netflix",
            Self::Harbor => "Cloud-native container image registry with security",
            Self::NexusRepo => "Repository manager for binary artifacts and packages",
            Self::Artifactory => "Universal binary repository manager by JFrog",
            Self::Verdaccio => "Lightweight private npm proxy registry",
            Self::Gitea => "Lightweight self-hosted Git service in Go",
            Self::Gogs => "Painless self-hosted Git service in Go",
            Self::Forgejo => "Community-managed fork of Gitea git hosting",
            Self::Concourse => "Open-source CI/CD pipeline automation system",

            // Monitoring & Observability
            Self::Kibana => "Data visualization dashboard for Elasticsearch",
            Self::Logstash => "Server-side data processing pipeline for logs",
            Self::Fluentd => "Unified logging layer for data collection",
            Self::FluentBit => "Lightweight log processor and forwarder",
            Self::Tempo => "High-volume distributed tracing backend by Grafana",
            Self::Loki => "Log aggregation system inspired by Prometheus",
            Self::AlertManager => "Alert routing and grouping for Prometheus",
            Self::Nagios => "Enterprise-class monitoring and alerting system",
            Self::Zabbix => "Enterprise monitoring solution for networks and apps",
            Self::Icinga => "Monitoring system forked from Nagios with modern UI",
            Self::Graylog => "Centralized log management and analysis platform",
            Self::Seq => "Structured log search and analysis server for .NET",
            Self::Vector => "High-performance observability data pipeline",
            Self::Telegraf => "Plugin-driven server agent for collecting metrics",
            Self::Netdata => "Real-time performance and health monitoring",
            Self::UptimeKuma => "Self-hosted monitoring tool like Uptime Robot",

            // Container & Orchestration
            Self::Containerd => "Industry-standard container runtime",
            Self::Etcd => "Distributed key-value store for shared configuration",
            Self::CoreDNS => "DNS server for Kubernetes service discovery",
            Self::Istio => "Service mesh for microservice networking and security",
            Self::Linkerd => "Ultralight service mesh for Kubernetes",
            Self::Nomad => "Workload orchestrator by HashiCorp",
            Self::Portainer => "Container management UI for Docker and Kubernetes",
            Self::Rancher => "Enterprise Kubernetes management platform",
            Self::K3s => "Lightweight certified Kubernetes distribution",

            // Game servers
            Self::Minecraft => "Sandbox game server for Java and Bedrock editions",
            Self::Factorio => "Factory building game dedicated server",
            Self::Terraria => "2D sandbox adventure game server",
            Self::Valheim => "Viking survival game dedicated server",
            Self::ArkServer => "ARK: Survival Evolved dedicated server",
            Self::RustGame => "Rust survival game dedicated server",
            Self::CounterStrike => "Counter-Strike dedicated game server",
            Self::TeamFortress2 => "Team Fortress 2 dedicated game server",
            Self::GarrysMod => "Garry's Mod dedicated game server",
            Self::SourceEngine => "Valve Source Engine dedicated game server",

            // Media servers
            Self::Emby => "Personal media server with apps for all devices",
            Self::Subsonic => "Web-based media streamer for music and video",
            Self::Airsonic => "Free web-based media streaming server",
            Self::Navidrome => "Modern music server and streamer compatible with Subsonic",
            Self::MiniDLNA => "Lightweight DLNA/UPnP media server",
            Self::Icecast => "Open-source streaming media server for audio",
            Self::SHOUTcast => "Internet radio streaming server",
            Self::Mumble => "Low-latency voice chat for gaming",
            Self::TeamSpeak => "Voice communication for online gaming",

            // Home automation
            Self::HomeAssistant => "Open-source home automation platform",
            Self::OpenHAB => "Vendor-neutral open-source home automation",
            Self::Domoticz => "Lightweight home automation system",
            Self::NodeRED => "Flow-based programming for IoT automation",
            Self::PiHole => "Network-wide ad blocking via DNS sinkhole",
            Self::AdGuardHome => "Network-wide ad and tracker blocking DNS server",
            Self::Homebridge => "HomeKit support for smart home devices",

            // VPN & Network
            Self::OpenVPN => "Open-source VPN solution using SSL/TLS",
            Self::WireGuard => "Fast modern secure VPN tunnel protocol",
            Self::StrongSwan => "IPsec-based VPN solution for Linux",
            Self::Shadowsocks => "Secure SOCKS5 proxy for internet privacy",
            Self::V2Ray => "Platform for building network proxy tools",
            Self::Tailscale => "Zero-config mesh VPN built on WireGuard",
            Self::ZeroTier => "Software-defined networking for global connectivity",
            Self::Headscale => "Open-source Tailscale control server",

            // Mail servers (additional)
            Self::Sendmail => "Classic Unix mail transfer agent",
            Self::Exim => "Message transfer agent for Unix systems",
            Self::CyrusIMAP => "Scalable IMAP and POP3 email server",
            Self::HMailServer => "Free email server for Windows",
            Self::Zimbra => "Enterprise email and collaboration platform",
            Self::Haraka => "High-performance SMTP server in Node.js",

            // Windows services (additional)
            Self::FileZillaServer => "Open-source FTP and FTPS server for Windows",
            Self::TightVNC => "Free remote desktop software for Windows",
            Self::UltraVNC => "Remote access software for Windows systems",
            Self::RealVNC => "Remote access and control software",
            Self::Syncthing => "Continuous file synchronization between devices",
            Self::ResilioSync => "Peer-to-peer file synchronization tool",
            Self::EverythingSearch => "Instant file search engine for Windows",
            Self::WAMP => "Windows Apache MySQL PHP development stack",
            Self::XAMPP => "Cross-platform Apache MySQL PHP Perl stack",
            Self::Laragon => "Portable isolated development environment for Windows",

            Self::AndroidAdb => "Android Debug Bridge for device communication and development",
            Self::Bonjour => "Apple Bonjour zero-configuration networking (mDNS/DNS-SD)",
            Self::NordVPN => "NordVPN VPN client background service",
            Self::AppleMobileDevice => "Apple Mobile Device Service for iOS device sync",
            Self::IntelSUR => "Intel Software Update and Retrieval service",
            Self::HyperVManager => "Microsoft Hyper-V Virtual Machine Management Service",

            Self::RpcEndpointMapper => "Windows RPC Endpoint Mapper for DCOM and RPC services",
            Self::SSDP => "Simple Service Discovery Protocol for UPnP device discovery",
            Self::IPsec => "Internet Key Exchange for IPsec VPN tunnels",
            Self::LLMNR => "Link-Local Multicast Name Resolution for local hostname lookup",
            Self::CDPSvc => "Windows Connected Devices Platform for device pairing",
            Self::QWAVE => "Quality Windows Audio Video Experience for streaming QoS",
            Self::FDResPub => "Function Discovery Resource Publication for UPnP/WSD",
            Self::IpHelper => "Windows IP Helper for IPv6 transition and Teredo tunneling",
            Self::WindowsEventLog => "Windows Event Log RPC service endpoint",
            Self::TaskScheduler => "Windows Task Scheduler RPC service endpoint",
            Self::InternetConnectionSharing => "Windows Internet Connection Sharing (DNS/DHCP relay)",

            Self::CustomHttp => "Unidentified HTTP server responding on this port",
            Self::GenericTcp => "Unknown TCP service listening for connections",
            Self::GenericUdp => "Unknown UDP service accepting datagrams",
            Self::Unknown => "Unidentified service detected on this port",
        }
    }

    /// Rich Unicode symbol/emoji for each technology.
    pub fn unicode_icon(&self) -> &str {
        match self {
            // Web servers
            Self::Nginx => "\u{1F310}",
            Self::Apache => "\u{1F30D}",
            Self::IIS => "\u{1F3E2}",
            Self::Caddy => "\u{1F512}",
            Self::LiteSpeed => "\u{26A1}",
            Self::Traefik => "\u{1F6E4}",

            // App runtimes
            Self::NodeJs => "\u{2B22}",
            Self::Deno => "\u{1F995}",
            Self::Bun => "\u{1F35E}",
            Self::Python | Self::Django | Self::Flask | Self::FastAPI
            | Self::Uvicorn | Self::Gunicorn => "\u{1F40D}",
            Self::Ruby | Self::Rails => "\u{1F48E}",
            Self::PhpBuiltIn => "\u{1F418}",
            Self::JavaSpringBoot | Self::JavaTomcat => "\u{2615}",
            Self::DotNetKestrel => "\u{1F7E3}",
            Self::GoHttp => "\u{1F439}",
            Self::RustActix | Self::RustAxum => "\u{2699}",

            // Databases
            Self::PostgreSQL => "\u{1F418}",
            Self::MySQL | Self::MariaDB => "\u{1F42C}",
            Self::MongoDB => "\u{1F343}",
            Self::Redis => "\u{1F534}",
            Self::SQLite => "\u{1F4BE}",
            Self::Memcached => "\u{1F9E0}",
            Self::Elasticsearch => "\u{1F50D}",
            Self::ClickHouse => "\u{1F3E0}",
            Self::CockroachDB => "\u{1FAB3}",

            // Message brokers
            Self::RabbitMQ => "\u{1F407}",
            Self::Kafka => "\u{1F4E8}",
            Self::NATS => "\u{1F4EC}",
            Self::Mosquitto => "\u{1F99F}",

            // Dev tools
            Self::ViteDevServer => "\u{26A1}",
            Self::WebpackDevServer => "\u{1F4E6}",
            Self::NextJs => "\u{25B6}",
            Self::Remix => "\u{1F4BF}",
            Self::CreateReactApp => "\u{269B}",
            Self::AngularCli => "\u{1F6E1}",
            Self::VueCli => "\u{1F49A}",
            Self::SvelteKit => "\u{1F525}",
            Self::Astro => "\u{1F680}",
            Self::Hugo => "\u{1F4DD}",
            Self::Gatsby => "\u{1F7E3}",
            Self::Storybook => "\u{1F4D6}",

            // Infrastructure
            Self::Docker => "\u{1F433}",
            Self::Kubernetes => "\u{2638}",
            Self::Prometheus => "\u{1F525}",
            Self::Grafana => "\u{1F4CA}",
            Self::Jenkins => "\u{1F477}",
            Self::GitLabRunner => "\u{1F98A}",
            Self::Consul => "\u{1F3DB}",
            Self::Vault => "\u{1F510}",
            Self::MinIO => "\u{1F5C4}",
            Self::NginxProxyManager => "\u{1F6E1}",

            // System services
            Self::OpenSSH => "\u{1F511}",
            Self::SMB => "\u{1F4C1}",
            Self::DNS => "\u{1F4F6}",
            Self::DHCP => "\u{1F4E1}",
            Self::FTP => "\u{1F4E4}",
            Self::SMTP => "\u{2709}",
            Self::RDP => "\u{1F5A5}",
            Self::VNC => "\u{1F4F1}",
            Self::WinRM => "\u{1F4BB}",
            Self::PrintSpooler => "\u{1F5A8}",

            // Web frameworks
            Self::Express | Self::Fastify | Self::Sanic | Self::Fiber => "\u{26A1}",
            Self::Koa => "\u{1F343}",
            Self::NestJS => "\u{1F431}",
            Self::Hapi => "\u{1F537}",
            Self::Nuxt => "\u{1F49A}",
            Self::AdonisJS => "\u{1F49C}",
            Self::Tornado => "\u{1F32A}",
            Self::Starlette => "\u{2B50}",
            Self::Bottle => "\u{1F37E}",
            Self::CherryPy => "\u{1F352}",
            Self::Laravel => "\u{1F534}",
            Self::Symfony => "\u{26AB}",
            Self::WordPress => "\u{1F4DD}",
            Self::Drupal => "\u{1F4A7}",
            Self::Micronaut => "\u{1F52C}",
            Self::Quarkus => "\u{1F537}",
            Self::Gin => "\u{1F378}",
            Self::Echo => "\u{1F4E2}",
            Self::Ghost => "\u{1F47B}",
            Self::Strapi => "\u{1F680}",

            // Additional web servers / proxies
            Self::Jetty => "\u{2615}",
            Self::HAProxy => "\u{2696}",
            Self::Varnish => "\u{1F680}",

            // Additional app runtimes
            Self::WildFly => "\u{1F98A}",
            Self::Plex => "\u{1F3AC}",
            Self::Jellyfin => "\u{1F3B5}",

            // Additional databases
            Self::MSSQL => "\u{1F5C4}",
            Self::CouchDB => "\u{1F6CB}",
            Self::Neo4j => "\u{1F535}",
            Self::InfluxDB => "\u{1F4C8}",
            Self::Cassandra => "\u{1F441}",
            Self::Solr => "\u{1F50E}",
            Self::MeiliSearch => "\u{1F50D}",
            Self::Typesense => "\u{1F524}",

            // Additional dev tools
            Self::Jupyter => "\u{1F4D3}",
            Self::PgAdmin => "\u{1F418}",
            Self::Swagger => "\u{1F4CB}",

            // Additional infrastructure
            Self::Envoy => "\u{1F310}",
            Self::Jaeger => "\u{1F52D}",
            Self::Zipkin => "\u{1F52C}",
            Self::Keycloak => "\u{1F510}",
            Self::Kong => "\u{1F98D}",

            // Additional system services
            Self::Postfix => "\u{1F4EE}",
            Self::Dovecot => "\u{1F54A}",

            // Additional databases
            Self::ScyllaDB | Self::TiDB | Self::YugabyteDB | Self::RethinkDB
            | Self::ArangoDB | Self::OrientDB | Self::DGraph | Self::TimescaleDB
            | Self::QuestDB | Self::DuckDB | Self::Firebird | Self::OracleDB
            | Self::DB2 => "\u{1F5C4}",
            Self::Vitess | Self::ProxySQL | Self::MaxScale | Self::PgBouncer
            | Self::Pgpool => "\u{2696}",

            // Additional message brokers
            Self::ActiveMQ | Self::Pulsar | Self::RocketMQ | Self::NSQ
            | Self::Beanstalkd => "\u{1F4E8}",
            Self::HiveMQ | Self::EMQX | Self::VerneMQ => "\u{1F99F}",

            // Additional web servers
            Self::OpenResty | Self::Tengine => "\u{1F310}",
            Self::H2O | Self::Cherokee | Self::Mongoose | Self::Pound => "\u{1F310}",
            Self::Squid | Self::Privoxy => "\u{1F6E1}",

            // Dev tools (additional)
            Self::Parcel | Self::Snowpack | Self::Esbuild => "\u{1F4E6}",
            Self::BrowserSync | Self::LiveReload => "\u{1F504}",
            Self::JupyterHub => "\u{1F4D3}",
            Self::RStudioServer => "\u{1F4CA}",
            Self::CodeServer => "\u{1F4BB}",
            Self::Ngrok => "\u{1F310}",
            Self::Cypress | Self::Playwright | Self::SeleniumGrid => "\u{1F9EA}",

            // CI/CD & DevOps
            Self::TeamCity | Self::Bamboo | Self::DroneCI | Self::GoCD
            | Self::ArgoCD | Self::Tekton | Self::BuildkiteAgent
            | Self::WoodpeckerCI | Self::Spinnaker | Self::Concourse => "\u{1F477}",
            Self::Harbor | Self::NexusRepo | Self::Artifactory | Self::Verdaccio => "\u{1F4E6}",
            Self::Gitea | Self::Gogs | Self::Forgejo => "\u{1F98A}",

            // Monitoring & Observability
            Self::Kibana => "\u{1F4CA}",
            Self::Logstash | Self::Fluentd | Self::FluentBit | Self::Vector => "\u{1F4DD}",
            Self::Tempo | Self::Loki | Self::AlertManager => "\u{1F514}",
            Self::Nagios | Self::Zabbix | Self::Icinga => "\u{1F440}",
            Self::Graylog | Self::Seq => "\u{1F4D1}",
            Self::Telegraf | Self::Netdata | Self::UptimeKuma => "\u{1F4C8}",

            // Container & Orchestration
            Self::Containerd => "\u{1F4E6}",
            Self::Etcd => "\u{1F5C3}",
            Self::CoreDNS => "\u{1F4F6}",
            Self::Istio | Self::Linkerd => "\u{1F578}",
            Self::Nomad => "\u{1F3D5}",
            Self::Portainer | Self::Rancher => "\u{1F433}",
            Self::K3s => "\u{2638}",

            // Game servers
            Self::Minecraft => "\u{26CF}",
            Self::Factorio | Self::Terraria | Self::Valheim
            | Self::ArkServer | Self::RustGame => "\u{1F3AE}",
            Self::CounterStrike | Self::TeamFortress2
            | Self::GarrysMod | Self::SourceEngine => "\u{1F3AE}",

            // Media servers
            Self::Emby => "\u{1F3AC}",
            Self::Subsonic | Self::Airsonic | Self::Navidrome => "\u{1F3B5}",
            Self::MiniDLNA => "\u{1F4FA}",
            Self::Icecast | Self::SHOUTcast => "\u{1F4FB}",
            Self::Mumble | Self::TeamSpeak => "\u{1F3A4}",

            // Home automation
            Self::HomeAssistant | Self::OpenHAB | Self::Domoticz => "\u{1F3E0}",
            Self::NodeRED => "\u{1F534}",
            Self::PiHole | Self::AdGuardHome => "\u{1F6E1}",
            Self::Homebridge => "\u{1F3E0}",

            // VPN & Network
            Self::OpenVPN | Self::WireGuard | Self::StrongSwan
            | Self::Tailscale | Self::ZeroTier | Self::Headscale => "\u{1F510}",
            Self::Shadowsocks | Self::V2Ray => "\u{1F310}",

            // Mail servers (additional)
            Self::Sendmail | Self::Exim | Self::CyrusIMAP
            | Self::HMailServer | Self::Zimbra | Self::Haraka => "\u{2709}",

            // Windows services (additional)
            Self::FileZillaServer => "\u{1F4E4}",
            Self::TightVNC | Self::UltraVNC | Self::RealVNC => "\u{1F4F1}",
            Self::Syncthing | Self::ResilioSync => "\u{1F504}",
            Self::EverythingSearch => "\u{1F50D}",
            Self::WAMP | Self::XAMPP | Self::Laragon => "\u{1F4E6}",

            Self::AndroidAdb => "\u{1F4F1}",
            Self::Bonjour => "\u{1F4E2}",
            Self::NordVPN => "\u{1F510}",
            Self::AppleMobileDevice => "\u{1F34E}",
            Self::IntelSUR => "\u{1F4BB}",
            Self::HyperVManager => "\u{1F5A5}",

            Self::RpcEndpointMapper => "\u{1F517}",
            Self::SSDP => "\u{1F4E1}",
            Self::IPsec => "\u{1F512}",
            Self::LLMNR => "\u{1F4DB}",
            Self::CDPSvc => "\u{1F4F2}",
            Self::QWAVE => "\u{1F3B5}",
            Self::FDResPub => "\u{1F50D}",
            Self::IpHelper => "\u{1F310}",
            Self::WindowsEventLog => "\u{1F4CB}",
            Self::TaskScheduler => "\u{23F0}",
            Self::InternetConnectionSharing => "\u{1F4E1}",

            // Other
            Self::CustomHttp => "\u{1F310}",
            Self::GenericTcp => "\u{1F50C}",
            Self::GenericUdp => "\u{1F4E1}",
            Self::Unknown => "\u{2753}",
        }
    }
}

/// Category for grouping servers in the UI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServerCategory {
    WebServer,
    AppRuntime,
    WebFramework,
    DevTool,
    Database,
    MessageBroker,
    Infrastructure,
    SystemService,
    Other,
}

impl ServerCategory {
    pub fn label(&self) -> &str {
        match self {
            Self::WebServer => "Web Servers",
            Self::AppRuntime => "App Runtimes",
            Self::WebFramework => "Web Frameworks",
            Self::DevTool => "Dev Tools",
            Self::Database => "Databases",
            Self::MessageBroker => "Message Brokers",
            Self::Infrastructure => "Infrastructure",
            Self::SystemService => "System Services",
            Self::Other => "Other",
        }
    }

    pub fn color(&self) -> (u8, u8, u8) {
        match self {
            Self::WebServer => (0, 200, 120),       // green
            Self::AppRuntime => (80, 160, 255),      // blue
            Self::WebFramework => (140, 200, 255),   // light blue
            Self::DevTool => (255, 200, 50),         // yellow
            Self::Database => (200, 100, 255),       // purple
            Self::MessageBroker => (255, 140, 50),   // orange
            Self::Infrastructure => (100, 220, 220), // cyan
            Self::SystemService => (180, 180, 180),  // gray
            Self::Other => (120, 120, 120),          // dim gray
        }
    }
}

/// A single detected listening port with all gathered info.
#[derive(Clone, Debug)]
pub struct ListeningPort {
    /// Protocol (TCP or UDP).
    pub proto: ListenProto,
    /// Bind address.
    pub bind_addr: IpAddr,
    /// Port number.
    pub port: u16,
    /// Process ID.
    pub pid: u32,
    /// Process name (exe basename).
    pub process_name: String,
    /// Full executable path.
    pub exe_path: String,
    /// Command line arguments.
    pub cmdline: String,
    /// Detected server technology.
    pub server_kind: ServerKind,
    /// Server version string (from banner/probe).
    pub version: Option<String>,
    /// HTTP response title (if HTTP server).
    pub http_title: Option<String>,
    /// Raw banner text (first bytes received on connect).
    pub banner: Option<String>,
    /// HTTP response headers of interest.
    pub response_headers: Vec<(String, String)>,
    /// Number of active connections to this port.
    pub active_connections: u32,
    /// When this listener was first detected.
    pub first_seen: NaiveTime,
    /// Whether this listener is confirmed responding.
    pub is_responsive: bool,
    /// Additional technology details/notes.
    pub details: String,
    /// Additional technologies detected via HTTP headers (Wappalyzer-style).
    /// Each entry: (technology_name, category, version_or_empty).
    pub detected_techs: Vec<DetectedTech>,
}

/// A technology detected via HTTP header fingerprinting (Wappalyzer-style).
#[derive(Clone, Debug)]
pub struct DetectedTech {
    pub name: String,
    pub category: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenProto {
    Tcp,
    Udp,
}

impl ListenProto {
    pub fn label(&self) -> &str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}
