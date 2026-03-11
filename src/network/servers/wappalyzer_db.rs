//! Wappalyzer-style HTTP header fingerprint database.
//! Contains ~2000 technology signatures inspired by the Wappalyzer open-source
//! database (github.com/dochne/wappalyzer, GPLv3).
//!
//! These detect technologies purely from HTTP response headers — complementing
//! the main fingerprint database which uses process names, cmdlines, banners, etc.

use super::types::DetectedTech;

/// A single Wappalyzer header signature.
struct HeaderSig {
    /// Technology name (display label).
    name: &'static str,
    /// Category label.
    category: &'static str,
    /// Which header to check (lowercase).
    header: &'static str,
    /// Substring that must appear in the header value (lowercase). Empty = header existence is enough.
    pattern: &'static str,
    /// Prefix for version extraction from the header value (e.g., "nginx" extracts from "nginx/1.24").
    /// Empty = no version extraction.
    version_prefix: &'static str,
}

/// Master Wappalyzer header signature database.
/// Each entry matches a single (header_name, pattern) combination.
static SIGNATURES: &[HeaderSig] = &[
    // ═══════════════════════════════════════════════════════════════════════════
    // WEB SERVERS (Server header)
    // ═══════════════════════════════════════════════════════════════════════════
    HeaderSig { name: "Nginx", category: "Web Server", header: "server", pattern: "nginx", version_prefix: "nginx" },
    HeaderSig { name: "OpenResty", category: "Web Server", header: "server", pattern: "openresty", version_prefix: "openresty" },
    HeaderSig { name: "Angie", category: "Web Server", header: "server", pattern: "angie", version_prefix: "angie" },
    HeaderSig { name: "Apache HTTP Server", category: "Web Server", header: "server", pattern: "apache", version_prefix: "apache" },
    HeaderSig { name: "Apache Traffic Server", category: "Web Server", header: "server", pattern: "ats", version_prefix: "" },
    HeaderSig { name: "Microsoft IIS", category: "Web Server", header: "server", pattern: "microsoft-iis", version_prefix: "microsoft-iis" },
    HeaderSig { name: "Microsoft HTTPAPI", category: "Web Server", header: "server", pattern: "microsoft-httpapi", version_prefix: "microsoft-httpapi" },
    HeaderSig { name: "Caddy", category: "Web Server", header: "server", pattern: "caddy", version_prefix: "" },
    HeaderSig { name: "LiteSpeed", category: "Web Server", header: "server", pattern: "litespeed", version_prefix: "litespeed" },
    HeaderSig { name: "Traefik", category: "Reverse Proxy", header: "server", pattern: "traefik", version_prefix: "" },
    HeaderSig { name: "lighttpd", category: "Web Server", header: "server", pattern: "lighttpd", version_prefix: "lighttpd" },
    HeaderSig { name: "Cherokee", category: "Web Server", header: "server", pattern: "cherokee", version_prefix: "cherokee" },
    HeaderSig { name: "Hiawatha", category: "Web Server", header: "server", pattern: "hiawatha", version_prefix: "hiawatha" },
    HeaderSig { name: "H2O", category: "Web Server", header: "server", pattern: "h2o", version_prefix: "h2o" },
    HeaderSig { name: "Monkey HTTP Server", category: "Web Server", header: "server", pattern: "monkey", version_prefix: "monkey" },
    HeaderSig { name: "thttpd", category: "Web Server", header: "server", pattern: "thttpd", version_prefix: "thttpd" },
    HeaderSig { name: "GoAhead", category: "Web Server", header: "server", pattern: "goahead", version_prefix: "" },
    HeaderSig { name: "MiniServ", category: "Web Server", header: "server", pattern: "miniserv", version_prefix: "miniserv" },
    HeaderSig { name: "AOLserver", category: "Web Server", header: "server", pattern: "aolserver", version_prefix: "aolserver" },
    HeaderSig { name: "Xitami", category: "Web Server", header: "server", pattern: "xitami", version_prefix: "xitami" },
    HeaderSig { name: "Boa", category: "Web Server", header: "server", pattern: "boa", version_prefix: "" },
    HeaderSig { name: "Cowboy", category: "Web Server", header: "server", pattern: "cowboy", version_prefix: "" },
    HeaderSig { name: "Kestrel", category: "Web Server", header: "server", pattern: "kestrel", version_prefix: "" },
    HeaderSig { name: "Tengine", category: "Web Server", header: "server", pattern: "tengine", version_prefix: "tengine" },
    HeaderSig { name: "SimpleHTTP", category: "Web Server", header: "server", pattern: "simplehttp", version_prefix: "simplehttp" },
    HeaderSig { name: "Brimble", category: "Web Server", header: "server", pattern: "brimble", version_prefix: "" },
    HeaderSig { name: "Deta", category: "Cloud Platform", header: "server", pattern: "deta", version_prefix: "" },
    HeaderSig { name: "Indy", category: "Web Server", header: "server", pattern: "indy", version_prefix: "indy" },

    // ── Cloud / CDN servers ──
    HeaderSig { name: "Cloudflare", category: "CDN", header: "server", pattern: "cloudflare", version_prefix: "" },
    HeaderSig { name: "CDN77", category: "CDN", header: "server", pattern: "cdn77", version_prefix: "" },
    HeaderSig { name: "CacheFly", category: "CDN", header: "server", pattern: "cfs", version_prefix: "" },
    HeaderSig { name: "KeyCDN", category: "CDN", header: "server", pattern: "keycdn", version_prefix: "" },
    HeaderSig { name: "GoCache", category: "CDN", header: "server", pattern: "gocache", version_prefix: "" },
    HeaderSig { name: "Google Web Server", category: "Web Server", header: "server", pattern: "gws", version_prefix: "" },
    HeaderSig { name: "Amazon EC2", category: "Cloud Platform", header: "server", pattern: "amazon", version_prefix: "" },
    HeaderSig { name: "Amazon ELB", category: "Load Balancer", header: "server", pattern: "awselb", version_prefix: "" },
    HeaderSig { name: "Netlify", category: "Cloud Platform", header: "server", pattern: "netlify", version_prefix: "" },
    HeaderSig { name: "Fly.io", category: "Cloud Platform", header: "server", pattern: "fly/", version_prefix: "" },
    HeaderSig { name: "Vercel", category: "Cloud Platform", header: "server", pattern: "vercel", version_prefix: "" },
    HeaderSig { name: "Render", category: "Cloud Platform", header: "server", pattern: "render", version_prefix: "" },
    HeaderSig { name: "Heroku", category: "Cloud Platform", header: "server", pattern: "heroku", version_prefix: "" },
    HeaderSig { name: "Pantheon", category: "Cloud Platform", header: "server", pattern: "pantheon", version_prefix: "" },
    HeaderSig { name: "Pagely", category: "Hosting", header: "server", pattern: "pagely", version_prefix: "" },
    HeaderSig { name: "PythonAnywhere", category: "Hosting", header: "server", pattern: "pythonanywhere", version_prefix: "" },
    HeaderSig { name: "NexusPIPE", category: "Security", header: "server", pattern: "nexuspipe", version_prefix: "" },
    HeaderSig { name: "Fireblade", category: "Security", header: "server", pattern: "fbs", version_prefix: "" },
    HeaderSig { name: "F5 BIG-IP", category: "Load Balancer", header: "server", pattern: "big-ip", version_prefix: "" },
    HeaderSig { name: "F5 BIG-IP", category: "Load Balancer", header: "server", pattern: "bigip", version_prefix: "" },
    HeaderSig { name: "DiamondCDN", category: "CDN", header: "server", pattern: "diamondcdn", version_prefix: "" },
    HeaderSig { name: "Hostinger CDN", category: "CDN", header: "server", pattern: "hcdn", version_prefix: "" },
    HeaderSig { name: "TwicPics", category: "CDN", header: "server", pattern: "twicpics", version_prefix: "" },
    HeaderSig { name: "Imunify360", category: "Security", header: "server", pattern: "imunify360", version_prefix: "imunify360-webshield" },
    HeaderSig { name: "Combahton FlowShield", category: "Security", header: "server", pattern: "antiddos", version_prefix: "" },

    // ── Enterprise / Java servers ──
    HeaderSig { name: "GlassFish", category: "App Server", header: "server", pattern: "glassfish", version_prefix: "glassfish" },
    HeaderSig { name: "Jetty", category: "App Server", header: "server", pattern: "jetty", version_prefix: "jetty" },
    HeaderSig { name: "WebLogic Server", category: "App Server", header: "server", pattern: "weblogic", version_prefix: "weblogic" },
    HeaderSig { name: "Resin", category: "App Server", header: "server", pattern: "resin", version_prefix: "resin" },
    HeaderSig { name: "Oracle Application Server", category: "App Server", header: "server", pattern: "oracle-application-server", version_prefix: "" },
    HeaderSig { name: "Oracle HTTP Server", category: "App Server", header: "server", pattern: "oracle-http-server", version_prefix: "oracle-http-server" },
    HeaderSig { name: "Oracle Web Cache", category: "Cache", header: "server", pattern: "oracle-web-cache", version_prefix: "" },
    HeaderSig { name: "IBM HTTP Server", category: "Web Server", header: "server", pattern: "ibm_http_server", version_prefix: "ibm_http_server" },
    HeaderSig { name: "SAP NetWeaver", category: "App Server", header: "server", pattern: "sap netweaver", version_prefix: "" },
    HeaderSig { name: "Cloudera", category: "Data Platform", header: "server", pattern: "cloudera", version_prefix: "" },

    // ── Language-specific servers ──
    HeaderSig { name: "Werkzeug (Flask)", category: "Python Framework", header: "server", pattern: "werkzeug", version_prefix: "werkzeug" },
    HeaderSig { name: "Gunicorn", category: "Python Server", header: "server", pattern: "gunicorn", version_prefix: "gunicorn" },
    HeaderSig { name: "Uvicorn", category: "Python Server", header: "server", pattern: "uvicorn", version_prefix: "uvicorn" },
    HeaderSig { name: "Hypercorn", category: "Python Server", header: "server", pattern: "hypercorn", version_prefix: "hypercorn" },
    HeaderSig { name: "Daphne (Django ASGI)", category: "Python Server", header: "server", pattern: "daphne", version_prefix: "" },
    HeaderSig { name: "TornadoServer", category: "Python Framework", header: "server", pattern: "tornadoserver", version_prefix: "tornadoserver" },
    HeaderSig { name: "TwistedWeb", category: "Python Server", header: "server", pattern: "twistedweb", version_prefix: "twistedweb" },
    HeaderSig { name: "CherryPy", category: "Python Framework", header: "server", pattern: "cherrypy", version_prefix: "cherrypy" },
    HeaderSig { name: "Zope", category: "Python Framework", header: "server", pattern: "zope", version_prefix: "" },
    HeaderSig { name: "OpenSwoole", category: "PHP Framework", header: "server", pattern: "openswoole", version_prefix: "openswoole" },
    HeaderSig { name: "RoadRunner", category: "PHP Server", header: "server", pattern: "roadrunner", version_prefix: "" },
    HeaderSig { name: "Phusion Passenger", category: "App Server", header: "server", pattern: "phusion passenger", version_prefix: "phusion passenger" },
    HeaderSig { name: "WEBrick", category: "Ruby Server", header: "server", pattern: "webrick", version_prefix: "webrick" },
    HeaderSig { name: "Mongrel", category: "Ruby Server", header: "server", pattern: "mongrel", version_prefix: "" },
    HeaderSig { name: "Puma", category: "Ruby Server", header: "server", pattern: "puma", version_prefix: "puma" },
    HeaderSig { name: "MochiWeb", category: "Erlang Server", header: "server", pattern: "mochiweb", version_prefix: "mochiweb" },
    HeaderSig { name: "Mojolicious", category: "Perl Framework", header: "server", pattern: "mojolicious", version_prefix: "" },
    HeaderSig { name: "Dancer", category: "Perl Framework", header: "server", pattern: "perl dancer", version_prefix: "perl dancer" },
    HeaderSig { name: "Akka HTTP", category: "Scala Framework", header: "server", pattern: "akka-http", version_prefix: "" },
    HeaderSig { name: "Ktor", category: "Kotlin Framework", header: "server", pattern: "ktor", version_prefix: "" },
    HeaderSig { name: "Warp", category: "Haskell Framework", header: "server", pattern: "warp", version_prefix: "warp" },
    HeaderSig { name: "Shelf (Dart)", category: "Dart Framework", header: "server", pattern: "dart:io with shelf", version_prefix: "" },
    HeaderSig { name: "Deno", category: "JavaScript Runtime", header: "server", pattern: "deno", version_prefix: "deno" },
    HeaderSig { name: "Mastodon", category: "Social Media", header: "server", pattern: "mastodon", version_prefix: "" },

    // ── Hosting control panels ──
    HeaderSig { name: "DirectAdmin", category: "Control Panel", header: "server", pattern: "directadmin", version_prefix: "directadmin daemon" },
    HeaderSig { name: "Virtuoso", category: "Database", header: "server", pattern: "virtuoso", version_prefix: "virtuoso" },
    HeaderSig { name: "HCL Domino", category: "App Server", header: "server", pattern: "lotus-domino", version_prefix: "" },
    HeaderSig { name: "HP iLO", category: "Management", header: "server", pattern: "hp-ilo-server", version_prefix: "hp-ilo-server" },
    HeaderSig { name: "HP Compact Server", category: "Web Server", header: "server", pattern: "hp_compact_server", version_prefix: "hp_compact_server" },
    HeaderSig { name: "Intel AMT", category: "Management", header: "server", pattern: "intel(r) active management", version_prefix: "" },
    HeaderSig { name: "Hetzner", category: "Hosting", header: "server", pattern: "heray", version_prefix: "" },

    // ── eCommerce platforms ──
    HeaderSig { name: "VTEX", category: "eCommerce", header: "server", pattern: "vtex", version_prefix: "" },
    HeaderSig { name: "Salesforce Commerce Cloud", category: "eCommerce", header: "server", pattern: "demandware", version_prefix: "" },
    HeaderSig { name: "WiziShop", category: "eCommerce", header: "server", pattern: "wiziserver", version_prefix: "" },

    // ── Other Server: headers ──
    HeaderSig { name: "Varnish", category: "Cache", header: "server", pattern: "varnish", version_prefix: "varnish" },
    HeaderSig { name: "Envoy", category: "Proxy", header: "server", pattern: "envoy", version_prefix: "" },
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "server", pattern: "haproxy", version_prefix: "" },
    HeaderSig { name: "PRONOTE", category: "Education", header: "server", pattern: "pronote", version_prefix: "" },
    HeaderSig { name: "RainLoop", category: "Email", header: "server", pattern: "rainloop", version_prefix: "" },
    HeaderSig { name: "OpenCms", category: "CMS", header: "server", pattern: "opencms", version_prefix: "" },
    HeaderSig { name: "Yaws", category: "Web Server", header: "server", pattern: "yaws", version_prefix: "yaws" },
    HeaderSig { name: "Darwin", category: "Operating System", header: "server", pattern: "darwin", version_prefix: "" },
    HeaderSig { name: "CentOS", category: "Operating System", header: "server", pattern: "centos", version_prefix: "" },
    HeaderSig { name: "Fedora", category: "Operating System", header: "server", pattern: "fedora", version_prefix: "" },
    HeaderSig { name: "Ubuntu", category: "Operating System", header: "server", pattern: "ubuntu", version_prefix: "" },
    HeaderSig { name: "Debian", category: "Operating System", header: "server", pattern: "debian", version_prefix: "" },
    HeaderSig { name: "Red Hat", category: "Operating System", header: "server", pattern: "red hat", version_prefix: "" },
    HeaderSig { name: "SUSE", category: "Operating System", header: "server", pattern: "suse", version_prefix: "" },
    HeaderSig { name: "Scientific Linux", category: "Operating System", header: "server", pattern: "scientific linux", version_prefix: "" },
    HeaderSig { name: "Raspbian", category: "Operating System", header: "server", pattern: "raspbian", version_prefix: "" },
    HeaderSig { name: "UNIX", category: "Operating System", header: "server", pattern: "unix", version_prefix: "" },
    HeaderSig { name: "Fing", category: "Cloud Platform", header: "server", pattern: "fing", version_prefix: "" },
    HeaderSig { name: "Cactive Cloud", category: "Cloud Platform", header: "server", pattern: "cactive", version_prefix: "" },
    HeaderSig { name: "LlamaLink", category: "Cloud Platform", header: "server", pattern: "llamalink", version_prefix: "" },
    HeaderSig { name: "OpenGSE", category: "Web Server", header: "server", pattern: "gse", version_prefix: "" },
    HeaderSig { name: "Grafana", category: "Monitoring", header: "server", pattern: "grafana", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "server", pattern: "jenkins", version_prefix: "" },
    HeaderSig { name: "MinIO", category: "Object Storage", header: "server", pattern: "minio", version_prefix: "" },
    HeaderSig { name: "XeoraEngine", category: "Web Server", header: "server", pattern: "xeoraengine", version_prefix: "" },

    // ═══════════════════════════════════════════════════════════════════════════
    // X-POWERED-BY HEADER
    // ═══════════════════════════════════════════════════════════════════════════
    HeaderSig { name: "PHP", category: "Language", header: "x-powered-by", pattern: "php", version_prefix: "php" },
    HeaderSig { name: "ASP.NET", category: "Framework", header: "x-powered-by", pattern: "asp.net", version_prefix: "" },
    HeaderSig { name: "Express.js", category: "Node.js Framework", header: "x-powered-by", pattern: "express", version_prefix: "" },
    HeaderSig { name: "Next.js", category: "React Framework", header: "x-powered-by", pattern: "next.js", version_prefix: "" },
    HeaderSig { name: "Nuxt.js", category: "Vue Framework", header: "x-powered-by", pattern: "nuxt", version_prefix: "" },
    HeaderSig { name: "Koa", category: "Node.js Framework", header: "x-powered-by", pattern: "koa", version_prefix: "" },
    HeaderSig { name: "Hapi", category: "Node.js Framework", header: "x-powered-by", pattern: "hapi", version_prefix: "" },
    HeaderSig { name: "Hono", category: "Edge Framework", header: "x-powered-by", pattern: "hono", version_prefix: "" },
    HeaderSig { name: "total.js", category: "Node.js Framework", header: "x-powered-by", pattern: "total.js", version_prefix: "" },
    HeaderSig { name: "PencilBlue", category: "CMS", header: "x-powered-by", pattern: "pencilblue", version_prefix: "" },
    HeaderSig { name: "Blitz.js", category: "React Framework", header: "x-powered-by", pattern: "blitz", version_prefix: "" },
    HeaderSig { name: "Sails.js", category: "Node.js Framework", header: "x-powered-by", pattern: "sails", version_prefix: "" },

    // ── PHP frameworks ──
    HeaderSig { name: "Laravel", category: "PHP Framework", header: "x-powered-by", pattern: "laravel", version_prefix: "" },
    HeaderSig { name: "Symfony", category: "PHP Framework", header: "x-powered-by", pattern: "symfony", version_prefix: "" },
    HeaderSig { name: "ThinkPHP", category: "PHP Framework", header: "x-powered-by", pattern: "thinkphp", version_prefix: "" },
    HeaderSig { name: "CakePHP", category: "PHP Framework", header: "x-powered-by", pattern: "cakephp", version_prefix: "" },
    HeaderSig { name: "CodeIgniter", category: "PHP Framework", header: "x-powered-by", pattern: "codeigniter", version_prefix: "" },
    HeaderSig { name: "Fat-Free Framework", category: "PHP Framework", header: "x-powered-by", pattern: "fat-free", version_prefix: "" },
    HeaderSig { name: "Banshee", category: "PHP Framework", header: "x-powered-by", pattern: "banshee php framework", version_prefix: "banshee php framework" },
    HeaderSig { name: "TwistPHP", category: "PHP Framework", header: "x-powered-by", pattern: "twistphp", version_prefix: "" },
    HeaderSig { name: "KPHP", category: "PHP Runtime", header: "x-powered-by", pattern: "kphp", version_prefix: "kphp" },
    HeaderSig { name: "BoidCMS", category: "CMS", header: "x-powered-by", pattern: "boidcms", version_prefix: "" },
    HeaderSig { name: "Brownie", category: "CMS", header: "x-powered-by", pattern: "brownie", version_prefix: "" },
    HeaderSig { name: "FlexCMP", category: "CMS", header: "x-powered-by", pattern: "flexcmp", version_prefix: "" },
    HeaderSig { name: "ProcessWire", category: "CMS", header: "x-powered-by", pattern: "processwire", version_prefix: "" },
    HeaderSig { name: "MODX", category: "CMS", header: "x-powered-by", pattern: "modx", version_prefix: "" },
    HeaderSig { name: "Nepso", category: "CMS", header: "x-powered-by", pattern: "nepso", version_prefix: "" },

    // ── Python ──
    HeaderSig { name: "Django", category: "Python Framework", header: "x-powered-by", pattern: "django", version_prefix: "" },
    HeaderSig { name: "Flask", category: "Python Framework", header: "x-powered-by", pattern: "flask", version_prefix: "" },
    HeaderSig { name: "Mojolicious", category: "Perl Framework", header: "x-powered-by", pattern: "mojolicious", version_prefix: "" },
    HeaderSig { name: "Dancer", category: "Perl Framework", header: "x-powered-by", pattern: "perl dancer", version_prefix: "perl dancer" },

    // ── Java ──
    HeaderSig { name: "Java Servlet", category: "Java", header: "x-powered-by", pattern: "servlet", version_prefix: "servlet" },
    HeaderSig { name: "JavaServer Faces", category: "Java Framework", header: "x-powered-by", pattern: "jsf", version_prefix: "jsf" },
    HeaderSig { name: "JavaServer Pages", category: "Java", header: "x-powered-by", pattern: "jsp", version_prefix: "jsp" },
    HeaderSig { name: "JBoss", category: "App Server", header: "x-powered-by", pattern: "jboss", version_prefix: "jboss" },
    HeaderSig { name: "JBoss Web", category: "App Server", header: "x-powered-by", pattern: "jbossweb", version_prefix: "jbossweb" },
    HeaderSig { name: "Blade", category: "Java Framework", header: "x-powered-by", pattern: "blade", version_prefix: "blade" },
    HeaderSig { name: "Public CMS", category: "CMS", header: "x-powered-by", pattern: "publiccms", version_prefix: "" },

    // ── .NET ──
    HeaderSig { name: "Mono", category: ".NET Runtime", header: "x-powered-by", pattern: "mono", version_prefix: "" },
    HeaderSig { name: "Orchard Core", category: "CMS", header: "x-powered-by", pattern: "orchardcore", version_prefix: "" },

    // ── Ruby ──
    HeaderSig { name: "Ruby on Rails", category: "Ruby Framework", header: "x-powered-by", pattern: "rails", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Ruby Framework", header: "x-powered-by", pattern: "mod_rails", version_prefix: "" },
    HeaderSig { name: "Phusion Passenger", category: "App Server", header: "x-powered-by", pattern: "phusion passenger", version_prefix: "" },
    HeaderSig { name: "mod_rack", category: "Ruby Server", header: "x-powered-by", pattern: "mod_rack", version_prefix: "" },

    // ── Other languages ──
    HeaderSig { name: "Lua", category: "Language", header: "x-powered-by", pattern: "lua", version_prefix: "lua" },
    HeaderSig { name: "Kemal", category: "Crystal Framework", header: "x-powered-by", pattern: "kemal", version_prefix: "" },
    HeaderSig { name: "Kohana", category: "PHP Framework", header: "x-powered-by", pattern: "kohana", version_prefix: "kohana framework" },
    HeaderSig { name: "Liferay", category: "Java Platform", header: "x-powered-by", pattern: "liferay", version_prefix: "" },
    HeaderSig { name: "genezio", category: "Backend Platform", header: "x-powered-by", pattern: "genezio", version_prefix: "" },
    HeaderSig { name: "Jibres", category: "eCommerce", header: "x-powered-by", pattern: "jibres", version_prefix: "" },
    HeaderSig { name: "Directus", category: "Headless CMS", header: "x-powered-by", pattern: "directus", version_prefix: "" },
    HeaderSig { name: "Pimcore", category: "CMS", header: "x-powered-by", pattern: "pimcore", version_prefix: "" },

    // ── Hosting / Platform ──
    HeaderSig { name: "Plesk", category: "Control Panel", header: "x-powered-by", pattern: "plesk", version_prefix: "" },
    HeaderSig { name: "Centminmod", category: "Server Stack", header: "x-powered-by", pattern: "centminmod", version_prefix: "" },
    HeaderSig { name: "WP Engine", category: "Hosting", header: "x-powered-by", pattern: "wp engine", version_prefix: "" },
    HeaderSig { name: "WP Rocket", category: "Cache Plugin", header: "x-powered-by", pattern: "wp rocket", version_prefix: "wp rocket" },
    HeaderSig { name: "W3 Total Cache", category: "Cache Plugin", header: "x-powered-by", pattern: "w3 total cache", version_prefix: "w3 total cache" },
    HeaderSig { name: "wpCache", category: "Cache Plugin", header: "x-powered-by", pattern: "wpcache", version_prefix: "" },
    HeaderSig { name: "Mobify", category: "eCommerce", header: "x-powered-by", pattern: "mobify", version_prefix: "" },
    HeaderSig { name: "Hetzner", category: "Hosting", header: "x-powered-by", pattern: "hetzner", version_prefix: "" },
    HeaderSig { name: "Helhost", category: "Hosting", header: "x-powered-by", pattern: "helhost", version_prefix: "" },
    HeaderSig { name: "Niagahoster", category: "Hosting", header: "x-powered-by", pattern: "niagahoster", version_prefix: "" },
    HeaderSig { name: "Nestify", category: "Hosting", header: "x-powered-by", pattern: "nestify", version_prefix: "" },
    HeaderSig { name: "PlatformOS", category: "Platform", header: "x-powered-by", pattern: "platformos", version_prefix: "" },
    HeaderSig { name: "Ikas", category: "eCommerce", header: "x-powered-by", pattern: "ikas", version_prefix: "" },
    HeaderSig { name: "Sirclo", category: "eCommerce", header: "x-powered-by", pattern: "sirclo", version_prefix: "" },
    HeaderSig { name: "Shopfa", category: "eCommerce", header: "x-powered-by", pattern: "shopfa", version_prefix: "" },
    HeaderSig { name: "Commerce.js", category: "eCommerce", header: "x-powered-by", pattern: "commerce.js", version_prefix: "" },
    HeaderSig { name: "Orckestra", category: "eCommerce", header: "x-powered-by", pattern: "orckestra", version_prefix: "" },
    HeaderSig { name: "TotalCode", category: "eCommerce", header: "x-powered-by", pattern: "totalcode", version_prefix: "" },
    HeaderSig { name: "Vanilla", category: "Forum", header: "x-powered-by", pattern: "vanilla", version_prefix: "" },
    HeaderSig { name: "RX Web Server", category: "Web Server", header: "x-powered-by", pattern: "rx-web", version_prefix: "" },
    HeaderSig { name: "HHVM", category: "PHP Runtime", header: "x-powered-by", pattern: "hhvm", version_prefix: "hhvm" },
    HeaderSig { name: "Brightspot", category: "CMS", header: "x-powered-by", pattern: "brightspot", version_prefix: "" },
    HeaderSig { name: "MasterkinG32", category: "Framework", header: "x-powered-by", pattern: "masterking", version_prefix: "" },
    HeaderSig { name: "HeliumWeb", category: "Framework", header: "x-powered-by", pattern: "adrikikicp", version_prefix: "" },
    HeaderSig { name: "LiveStreet CMS", category: "CMS", header: "x-powered-by", pattern: "livestreet", version_prefix: "" },
    HeaderSig { name: "Zend", category: "PHP Framework", header: "x-powered-by", pattern: "zend", version_prefix: "zend" },
    HeaderSig { name: "OTRS", category: "Ticketing", header: "x-powered-by", pattern: "otrs", version_prefix: "otrs" },
    HeaderSig { name: "Akaunting", category: "Accounting", header: "x-powered-by", pattern: "akaunting", version_prefix: "" },
    HeaderSig { name: "XeoraCube", category: "Framework", header: "x-powered-by", pattern: "xeoracube", version_prefix: "" },
    HeaderSig { name: "Virgool", category: "Blog Platform", header: "x-powered-by", pattern: "virgool", version_prefix: "" },
    HeaderSig { name: "YouCan", category: "eCommerce", header: "x-powered-by", pattern: "youcan", version_prefix: "" },
    HeaderSig { name: "Chamilo", category: "LMS", header: "x-powered-by", pattern: "chamilo", version_prefix: "chamilo" },

    // ── Additional X-Powered-By from Wappalyzer (batch 2 — 100+ new entries) ──
    HeaderSig { name: "Aegea", category: "Blog Engine", header: "x-powered-by", pattern: "aegea", version_prefix: "" },
    HeaderSig { name: "Alpine Linux", category: "Operating System", header: "x-powered-by", pattern: "alpine", version_prefix: "" },
    HeaderSig { name: "Amber", category: "Framework", header: "x-powered-by", pattern: "amber", version_prefix: "" },
    HeaderSig { name: "Apache Tomcat", category: "App Server", header: "x-powered-by", pattern: "tomcat", version_prefix: "tomcat" },
    HeaderSig { name: "Apache Coyote", category: "App Server", header: "server", pattern: "apache-coyote", version_prefix: "" },
    HeaderSig { name: "ApexPages", category: "Cloud Platform", header: "x-powered-by", pattern: "salesforce", version_prefix: "" },
    HeaderSig { name: "Catberry.js", category: "Node.js Framework", header: "x-powered-by", pattern: "catberry", version_prefix: "" },
    HeaderSig { name: "CPG Dragonfly", category: "CMS", header: "x-powered-by", pattern: "dragonfly cms", version_prefix: "" },
    HeaderSig { name: "DataDome", category: "Security", header: "server", pattern: "datadome", version_prefix: "" },
    HeaderSig { name: "DDoS-Guard", category: "Security", header: "server", pattern: "ddos-guard", version_prefix: "" },
    HeaderSig { name: "DERAK.CLOUD", category: "CDN", header: "server", pattern: "derak.cloud", version_prefix: "" },
    HeaderSig { name: "EasyEngine", category: "Server Stack", header: "x-powered-by", pattern: "easyengine", version_prefix: "" },
    HeaderSig { name: "ELOG", category: "Web Server", header: "server", pattern: "elog http", version_prefix: "" },
    HeaderSig { name: "Embeddable Appweb", category: "Web Server", header: "server", pattern: "mbedthis-appweb", version_prefix: "mbedthis-appweb" },
    HeaderSig { name: "Enduro.js", category: "Node.js CMS", header: "x-powered-by", pattern: "enduro", version_prefix: "" },
    HeaderSig { name: "Erlang", category: "Language", header: "server", pattern: "erlang", version_prefix: "" },
    HeaderSig { name: "eZ Publish", category: "CMS", header: "x-powered-by", pattern: "ez publish", version_prefix: "" },
    HeaderSig { name: "FreeBSD", category: "Operating System", header: "server", pattern: "freebsd", version_prefix: "" },
    HeaderSig { name: "GoAnywhere", category: "File Transfer", header: "server", pattern: "goanywhere", version_prefix: "" },
    HeaderSig { name: "HubSpot", category: "Marketing", header: "x-powered-by", pattern: "hubspot", version_prefix: "" },
    HeaderSig { name: "Hydra-Shield", category: "Security", header: "server", pattern: "hydra-shield", version_prefix: "" },
    HeaderSig { name: "libwww-perl-daemon", category: "Web Server", header: "server", pattern: "libwww-perl-daemon", version_prefix: "libwww-perl-daemon" },
    HeaderSig { name: "MATORI.NET", category: "Reverse Proxy", header: "x-powered-by", pattern: "matori.net", version_prefix: "" },
    HeaderSig { name: "MizbanCloud", category: "Cloud Platform", header: "server", pattern: "mizbancloud", version_prefix: "" },
    HeaderSig { name: "nghttp2", category: "HTTP/2 Server", header: "server", pattern: "nghttpx", version_prefix: "" },
    HeaderSig { name: "NodeBB", category: "Forum", header: "x-powered-by", pattern: "nodebb", version_prefix: "" },
    HeaderSig { name: "OpenBSD httpd", category: "Web Server", header: "server", pattern: "openbsd httpd", version_prefix: "" },
    HeaderSig { name: "OpenSSL", category: "Crypto Library", header: "server", pattern: "openssl", version_prefix: "openssl" },
    HeaderSig { name: "Perl", category: "Language", header: "server", pattern: "perl", version_prefix: "" },
    HeaderSig { name: "Riskified", category: "Security", header: "server", pattern: "riskified", version_prefix: "" },
    HeaderSig { name: "Roadiz CMS", category: "CMS", header: "x-powered-by", pattern: "roadiz", version_prefix: "" },
    HeaderSig { name: "BunnyCDN", category: "CDN", header: "server", pattern: "bunnycdn", version_prefix: "" },
    HeaderSig { name: "Amazon CloudFront", category: "CDN", header: "via", pattern: "cloudfront", version_prefix: "" },
    HeaderSig { name: "Amazon CloudFront", category: "CDN", header: "x-amz-cf-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Amazon ECS", category: "Container Platform", header: "server", pattern: "ecs", version_prefix: "" },
    HeaderSig { name: "Bluehost", category: "Hosting", header: "server", pattern: "bluehost", version_prefix: "" },
    HeaderSig { name: "Cloudways", category: "Hosting", header: "x-powered-by", pattern: "cloudways", version_prefix: "" },
    HeaderSig { name: "Elementor Cloud", category: "Hosting", header: "x-powered-by", pattern: "elementor cloud", version_prefix: "" },
    HeaderSig { name: "Canvas LMS", category: "LMS", header: "x-canvas-meta", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ckan", category: "Data Platform", header: "x-ckan-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Botble CMS", category: "CMS", header: "x-powered-by", pattern: "botble", version_prefix: "" },
    HeaderSig { name: "Adobe ColdFusion", category: "App Server", header: "set-cookie", pattern: "cftoken", version_prefix: "" },
    HeaderSig { name: "Clockwork", category: "Dev Tool", header: "x-clockwork-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Centra", category: "eCommerce", header: "x-powered-by", pattern: "centra", version_prefix: "" },
    HeaderSig { name: "Chabokan", category: "Cloud Platform", header: "x-powered-by", pattern: "chabokan", version_prefix: "" },
    HeaderSig { name: "ParminCloud", category: "Cloud Platform", header: "x-powered-by", pattern: "parmincloud", version_prefix: "" },
    HeaderSig { name: "Pagefai CMS", category: "CMS", header: "x-powered-by", pattern: "pagefai", version_prefix: "" },
    HeaderSig { name: "Canny", category: "Feedback", header: "x-powered-by", pattern: "canny", version_prefix: "" },
    HeaderSig { name: "Carrot quest", category: "Marketing", header: "x-powered-by", pattern: "carrot quest", version_prefix: "" },

    // ── Additional Server: headers from Wappalyzer (batch 2) ──
    HeaderSig { name: "Splunk", category: "Analytics", header: "server", pattern: "splunkd", version_prefix: "splunkd" },
    HeaderSig { name: "Thin", category: "Ruby Server", header: "server", pattern: "thin", version_prefix: "thin" },
    HeaderSig { name: "Unicorn", category: "Ruby Server", header: "server", pattern: "unicorn", version_prefix: "" },
    HeaderSig { name: "Kestrel", category: "Web Server", header: "server", pattern: "microsoft-kestrel", version_prefix: "" },
    HeaderSig { name: "Caddy", category: "Web Server", header: "server", pattern: "caddy", version_prefix: "" },
    HeaderSig { name: "Gunicorn", category: "Python Server", header: "server", pattern: "gunicorn", version_prefix: "gunicorn" },
    HeaderSig { name: "Starlette", category: "Python Framework", header: "server", pattern: "starlette", version_prefix: "" },
    HeaderSig { name: "FastAPI", category: "Python Framework", header: "server", pattern: "fastapi", version_prefix: "" },
    HeaderSig { name: "Sanic", category: "Python Framework", header: "server", pattern: "sanic", version_prefix: "" },
    HeaderSig { name: "aiohttp", category: "Python Server", header: "server", pattern: "aiohttp", version_prefix: "aiohttp" },
    HeaderSig { name: "Bottle", category: "Python Framework", header: "server", pattern: "bottle", version_prefix: "" },
    HeaderSig { name: "Waitress", category: "Python Server", header: "server", pattern: "waitress", version_prefix: "waitress" },
    HeaderSig { name: "Gin", category: "Go Framework", header: "server", pattern: "gin", version_prefix: "" },
    HeaderSig { name: "Fiber", category: "Go Framework", header: "server", pattern: "fiber", version_prefix: "" },
    HeaderSig { name: "Echo", category: "Go Framework", header: "server", pattern: "echo", version_prefix: "" },
    HeaderSig { name: "Actix Web", category: "Rust Framework", header: "server", pattern: "actix-web", version_prefix: "actix-web" },
    HeaderSig { name: "Axum", category: "Rust Framework", header: "server", pattern: "axum", version_prefix: "" },
    HeaderSig { name: "Rocket", category: "Rust Framework", header: "server", pattern: "rocket", version_prefix: "rocket" },
    HeaderSig { name: "Warp", category: "Rust Framework", header: "server", pattern: "warp", version_prefix: "warp" },
    HeaderSig { name: "Tide", category: "Rust Framework", header: "server", pattern: "tide", version_prefix: "" },
    HeaderSig { name: "Spring Boot", category: "Java Framework", header: "server", pattern: "spring", version_prefix: "" },
    HeaderSig { name: "Micronaut", category: "Java Framework", header: "server", pattern: "micronaut", version_prefix: "" },
    HeaderSig { name: "Quarkus", category: "Java Framework", header: "server", pattern: "quarkus", version_prefix: "" },
    HeaderSig { name: "Vert.x", category: "Java Framework", header: "server", pattern: "vert.x", version_prefix: "" },
    HeaderSig { name: "Undertow", category: "Java Server", header: "server", pattern: "undertow", version_prefix: "" },
    HeaderSig { name: "Ratpack", category: "Java Framework", header: "server", pattern: "ratpack", version_prefix: "" },
    HeaderSig { name: "Grizzly", category: "Java Server", header: "server", pattern: "grizzly", version_prefix: "grizzly" },
    HeaderSig { name: "Phoenix", category: "Elixir Framework", header: "server", pattern: "phoenix", version_prefix: "" },
    HeaderSig { name: "Plug (Elixir)", category: "Elixir Framework", header: "server", pattern: "plug", version_prefix: "" },
    HeaderSig { name: "Swoole", category: "PHP Framework", header: "server", pattern: "swoole", version_prefix: "swoole" },
    HeaderSig { name: "FrankenPHP", category: "PHP Server", header: "server", pattern: "frankenphp", version_prefix: "" },
    HeaderSig { name: "Laravel Octane", category: "PHP Framework", header: "server", pattern: "laravel octane", version_prefix: "" },
    HeaderSig { name: "NestJS", category: "Node.js Framework", header: "x-powered-by", pattern: "nest", version_prefix: "" },
    HeaderSig { name: "Fastify", category: "Node.js Framework", header: "x-powered-by", pattern: "fastify", version_prefix: "" },
    HeaderSig { name: "AdonisJS", category: "Node.js Framework", header: "x-powered-by", pattern: "adonisjs", version_prefix: "" },
    HeaderSig { name: "Strapi", category: "Headless CMS", header: "x-powered-by", pattern: "strapi", version_prefix: "" },
    HeaderSig { name: "Ghost", category: "CMS", header: "x-powered-by", pattern: "ghost", version_prefix: "" },
    HeaderSig { name: "KeystoneJS", category: "Node.js CMS", header: "x-powered-by", pattern: "keystonejs", version_prefix: "" },
    HeaderSig { name: "Payload CMS", category: "Node.js CMS", header: "x-powered-by", pattern: "payload", version_prefix: "" },
    HeaderSig { name: "Medusa", category: "eCommerce", header: "x-powered-by", pattern: "medusa", version_prefix: "" },
    HeaderSig { name: "Docusaurus", category: "Documentation", header: "x-powered-by", pattern: "docusaurus", version_prefix: "" },
    HeaderSig { name: "Redwood.js", category: "Full-Stack Framework", header: "x-powered-by", pattern: "redwoodjs", version_prefix: "" },
    HeaderSig { name: "Remix", category: "React Framework", header: "x-powered-by", pattern: "remix", version_prefix: "" },
    HeaderSig { name: "SvelteKit", category: "Svelte Framework", header: "x-powered-by", pattern: "sveltekit", version_prefix: "" },
    HeaderSig { name: "Astro", category: "Static Site Builder", header: "x-powered-by", pattern: "astro", version_prefix: "" },
    HeaderSig { name: "Gatsby", category: "React Framework", header: "x-powered-by", pattern: "gatsby", version_prefix: "" },
    HeaderSig { name: "Hugo", category: "Static Site Generator", header: "x-powered-by", pattern: "hugo", version_prefix: "" },
    HeaderSig { name: "11ty (Eleventy)", category: "Static Site Generator", header: "x-powered-by", pattern: "eleventy", version_prefix: "" },
    HeaderSig { name: "Hexo", category: "Static Site Generator", header: "x-powered-by", pattern: "hexo", version_prefix: "" },
    HeaderSig { name: "Jekyll", category: "Static Site Generator", header: "x-powered-by", pattern: "jekyll", version_prefix: "" },
    HeaderSig { name: "Pelican", category: "Static Site Generator", header: "x-powered-by", pattern: "pelican", version_prefix: "" },

    // ── OS detection via X-Powered-By ──
    HeaderSig { name: "Ubuntu", category: "Operating System", header: "x-powered-by", pattern: "ubuntu", version_prefix: "" },
    HeaderSig { name: "Debian", category: "Operating System", header: "x-powered-by", pattern: "debian", version_prefix: "" },
    HeaderSig { name: "Red Hat", category: "Operating System", header: "x-powered-by", pattern: "red hat", version_prefix: "" },
    HeaderSig { name: "SUSE", category: "Operating System", header: "x-powered-by", pattern: "suse", version_prefix: "" },
    HeaderSig { name: "Gentoo", category: "Operating System", header: "x-powered-by", pattern: "gentoo", version_prefix: "" },
    HeaderSig { name: "Raspbian", category: "Operating System", header: "x-powered-by", pattern: "raspbian", version_prefix: "" },
    HeaderSig { name: "Darwin", category: "Operating System", header: "x-powered-by", pattern: "darwin", version_prefix: "" },

    // ═══════════════════════════════════════════════════════════════════════════
    // SPECIAL HEADERS (not Server/X-Powered-By)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── ASP.NET version ──
    HeaderSig { name: "ASP.NET", category: "Framework", header: "x-aspnet-version", pattern: "", version_prefix: "" },

    // ── Via header ──
    HeaderSig { name: "Varnish", category: "Cache", header: "via", pattern: "varnish", version_prefix: "varnish" },
    HeaderSig { name: "Kong", category: "API Gateway", header: "via", pattern: "kong", version_prefix: "kong" },
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "via", pattern: "haproxy", version_prefix: "" },
    HeaderSig { name: "Squid", category: "Proxy", header: "via", pattern: "squid", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN", header: "via", pattern: "akamai", version_prefix: "" },

    // ── Technology-specific headers ──
    HeaderSig { name: "Cloudflare", category: "CDN", header: "cf-ray", pattern: "", version_prefix: "" },
    HeaderSig { name: "Cloudflare", category: "CDN", header: "cf-cache-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Envoy", category: "Proxy", header: "x-envoy-upstream-service-time", pattern: "", version_prefix: "" },
    HeaderSig { name: "Varnish", category: "Cache", header: "x-varnish", pattern: "", version_prefix: "" },
    HeaderSig { name: "Varnish", category: "Cache", header: "x-varnish-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Fastly", category: "CDN", header: "x-fastly-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Fastly", category: "CDN", header: "x-served-by", pattern: "cache-", version_prefix: "" },
    HeaderSig { name: "Amazon Web Services", category: "Cloud Platform", header: "x-amz-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Amazon S3", category: "Object Storage", header: "x-amz-bucket-region", pattern: "", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN", header: "x-akamai-transformed", pattern: "", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN", header: "x-edgeconnect-midmile-rtt", pattern: "", version_prefix: "" },
    HeaderSig { name: "Microsoft SharePoint", category: "Collaboration", header: "microsoftsharepointteamservices", pattern: "", version_prefix: "" },
    HeaderSig { name: "Microsoft SharePoint", category: "Collaboration", header: "sharepointheealthscore", pattern: "", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "x-drupal-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "x-generator", pattern: "drupal", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "x-generator", pattern: "wordpress", version_prefix: "" },
    HeaderSig { name: "Ghost", category: "CMS", header: "x-ghost-cache-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "x-jenkins", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "x-jenkins-session", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kibana", category: "Analytics", header: "kbn-name", pattern: "kibana", version_prefix: "" },
    HeaderSig { name: "Kibana", category: "Analytics", header: "kbn-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Elasticsearch", category: "Search Engine", header: "x-elastic-product", pattern: "elasticsearch", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Ruby Framework", header: "x-runtime", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Ruby Framework", header: "x-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Neos CMS", category: "CMS", header: "x-flow-powered", pattern: "neos", version_prefix: "" },
    HeaderSig { name: "Neos Flow", category: "PHP Framework", header: "x-flow-powered", pattern: "flow", version_prefix: "" },
    HeaderSig { name: "Ibexa DXP", category: "CMS", header: "x-powered-by", pattern: "ibexa", version_prefix: "" },
    HeaderSig { name: "Flywheel", category: "Hosting", header: "x-fw-server", pattern: "flywheel", version_prefix: "flywheel" },
    HeaderSig { name: "Nexcess", category: "Hosting", header: "x-hostname", pattern: "nxcli.net", version_prefix: "" },
    HeaderSig { name: "PyroCMS", category: "CMS", header: "x-streams-distribution", pattern: "pyrocms", version_prefix: "" },
    HeaderSig { name: "Apache APISIX", category: "API Gateway", header: "server", pattern: "apisix", version_prefix: "" },
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "x-haproxy-server-state", pattern: "", version_prefix: "" },
    HeaderSig { name: "Netlify", category: "Cloud Platform", header: "x-nf-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "WordPress Super Cache", category: "Cache Plugin", header: "wp-super-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Danneo CMS", category: "CMS", header: "x-powered-by", pattern: "cms danneo", version_prefix: "" },
    HeaderSig { name: "Pars Elecom Portal", category: "CMS", header: "x-powered-by", pattern: "pars elecom", version_prefix: "" },

    // ── Cookie-based detection (via Set-Cookie header) ──
    HeaderSig { name: "Akamai Bot Manager", category: "Security", header: "set-cookie", pattern: "ak_bmsc", version_prefix: "" },
    HeaderSig { name: "Incapsula (Imperva)", category: "Security", header: "set-cookie", pattern: "incap_ses", version_prefix: "" },
    HeaderSig { name: "Sucuri", category: "Security", header: "set-cookie", pattern: "sucuri", version_prefix: "" },

    // ── Alibaba Cloud ──
    HeaderSig { name: "Alibaba Cloud OSS", category: "Object Storage", header: "x-oss-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Alibaba Cloud", category: "Cloud Platform", header: "x-oss-server-time", pattern: "", version_prefix: "" },

    // ── Misc custom headers ──
    HeaderSig { name: "Lift Framework", category: "Scala Framework", header: "x-lift-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kooboo CMS", category: "CMS", header: "x-kooboocms-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "PHPFusion", category: "CMS", header: "x-phpfusion", pattern: "", version_prefix: "" },
    HeaderSig { name: "Liferay", category: "Java Platform", header: "liferay-portal", pattern: "", version_prefix: "" },
    HeaderSig { name: "Commerce Server", category: "eCommerce", header: "commerce-server-software", pattern: "", version_prefix: "" },

    // ── Apache modules detected from Server header ──
    HeaderSig { name: "mod_ssl", category: "Apache Module", header: "server", pattern: "mod_ssl", version_prefix: "" },
    HeaderSig { name: "mod_perl", category: "Apache Module", header: "server", pattern: "mod_perl", version_prefix: "" },
    HeaderSig { name: "mod_python", category: "Apache Module", header: "server", pattern: "mod_python", version_prefix: "" },
    HeaderSig { name: "mod_wsgi", category: "Apache Module", header: "server", pattern: "mod_wsgi", version_prefix: "" },
    HeaderSig { name: "mod_fastcgi", category: "Apache Module", header: "server", pattern: "mod_fastcgi", version_prefix: "" },
    HeaderSig { name: "mod_jk", category: "Apache Module", header: "server", pattern: "mod_jk", version_prefix: "" },
    HeaderSig { name: "mod_dav", category: "Apache Module", header: "server", pattern: "mod_dav", version_prefix: "" },
    HeaderSig { name: "mod_auth_pam", category: "Apache Module", header: "server", pattern: "mod_auth_pam", version_prefix: "" },

    // =========================================================================
    // EXPANDED SIGNATURES DATABASE (~1500 additional entries)
    // Covers: web servers, proxies, CDNs, CMS, eCommerce, JS frameworks,
    // backend frameworks, analytics, security/WAF, hosting/PaaS, databases,
    // image CDN, consent management, CI/CD, API gateways, monitoring, IoT, etc.
    // =========================================================================

    // -- Web Server --
    HeaderSig { name: "Boa", category: "Web Server", header: "server", pattern: "boa", version_prefix: "boa" },
    HeaderSig { name: "CERN httpd", category: "Web Server", header: "server", pattern: "cern", version_prefix: "" },
    HeaderSig { name: "Caudium", category: "Web Server", header: "server", pattern: "caudium", version_prefix: "caudium" },
    HeaderSig { name: "mathopd", category: "Web Server", header: "server", pattern: "mathopd", version_prefix: "mathopd" },
    HeaderSig { name: "micro_httpd", category: "Web Server", header: "server", pattern: "micro_httpd", version_prefix: "" },
    HeaderSig { name: "mini_httpd", category: "Web Server", header: "server", pattern: "mini_httpd", version_prefix: "mini_httpd" },
    HeaderSig { name: "Nostromo", category: "Web Server", header: "server", pattern: "nostromo", version_prefix: "nostromo" },
    HeaderSig { name: "Null httpd", category: "Web Server", header: "server", pattern: "null httpd", version_prefix: "" },

    // -- Streaming Server --
    HeaderSig { name: "Icecast", category: "Streaming Server", header: "server", pattern: "icecast", version_prefix: "icecast" },

    // -- Web Server --
    HeaderSig { name: "GoTTY", category: "Web Server", header: "server", pattern: "gotty", version_prefix: "" },
    HeaderSig { name: "darkhttpd", category: "Web Server", header: "server", pattern: "darkhttpd", version_prefix: "darkhttpd" },
    HeaderSig { name: "Mongoose", category: "Web Server", header: "server", pattern: "mongoose", version_prefix: "mongoose" },
    HeaderSig { name: "uhttpd", category: "Web Server", header: "server", pattern: "uhttpd", version_prefix: "" },
    HeaderSig { name: "BusyBox httpd", category: "Web Server", header: "server", pattern: "busybox httpd", version_prefix: "" },

    // -- Embedded Web Server --
    HeaderSig { name: "lwIP", category: "Embedded Web Server", header: "server", pattern: "lwip", version_prefix: "" },

    // -- IoT Web Server --
    HeaderSig { name: "ESP8266", category: "IoT Web Server", header: "server", pattern: "esp8266", version_prefix: "" },
    HeaderSig { name: "ESP32", category: "IoT Web Server", header: "server", pattern: "esp32", version_prefix: "" },

    // -- Streaming Server --
    HeaderSig { name: "SHOUTcast", category: "Streaming Server", header: "server", pattern: "shoutcast", version_prefix: "shoutcast" },
    HeaderSig { name: "ShoutIRC", category: "Streaming Server", header: "server", pattern: "shoutirc", version_prefix: "" },

    // -- Proxy Server --
    HeaderSig { name: "Squid", category: "Proxy Server", header: "server", pattern: "squid", version_prefix: "squid" },
    HeaderSig { name: "Squid", category: "Proxy Server", header: "via", pattern: "squid", version_prefix: "" },
    HeaderSig { name: "Polipo", category: "Proxy Server", header: "via", pattern: "polipo", version_prefix: "" },
    HeaderSig { name: "Privoxy", category: "Proxy Server", header: "server", pattern: "privoxy", version_prefix: "privoxy" },
    HeaderSig { name: "Tinyproxy", category: "Proxy Server", header: "via", pattern: "tinyproxy", version_prefix: "" },
    HeaderSig { name: "Tinyproxy", category: "Proxy Server", header: "server", pattern: "tinyproxy", version_prefix: "tinyproxy" },
    HeaderSig { name: "mitmproxy", category: "Proxy Server", header: "server", pattern: "mitmproxy", version_prefix: "" },

    // -- Load Balancer --
    HeaderSig { name: "Pound", category: "Load Balancer", header: "server", pattern: "pound", version_prefix: "pound" },
    HeaderSig { name: "Pen", category: "Load Balancer", header: "server", pattern: "pen/", version_prefix: "pen" },
    HeaderSig { name: "Zen Load Balancer", category: "Load Balancer", header: "server", pattern: "zen load balancer", version_prefix: "" },
    HeaderSig { name: "LVS", category: "Load Balancer", header: "server", pattern: "lvs", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "Hiawatha", category: "Web Server", header: "server", pattern: "hiawatha", version_prefix: "hiawatha" },
    HeaderSig { name: "Abyss", category: "Web Server", header: "server", pattern: "abyss", version_prefix: "abyss" },
    HeaderSig { name: "Monkey HTTP", category: "Web Server", header: "server", pattern: "monkey", version_prefix: "monkey" },
    HeaderSig { name: "thttpd", category: "Web Server", header: "server", pattern: "thttpd", version_prefix: "thttpd" },
    HeaderSig { name: "Zeus", category: "Web Server", header: "server", pattern: "zeus", version_prefix: "zeus" },
    HeaderSig { name: "AOLserver", category: "Web Server", header: "server", pattern: "aolserver", version_prefix: "aolserver" },
    HeaderSig { name: "Roxen", category: "Web Server", header: "server", pattern: "roxen", version_prefix: "roxen" },
    HeaderSig { name: "Yaws", category: "Web Server", header: "server", pattern: "yaws", version_prefix: "yaws" },
    HeaderSig { name: "Cowboy", category: "Web Server", header: "server", pattern: "cowboy", version_prefix: "cowboy" },
    HeaderSig { name: "MochiWeb", category: "Web Server", header: "server", pattern: "mochiweb", version_prefix: "mochiweb" },
    HeaderSig { name: "Misultin", category: "Web Server", header: "server", pattern: "misultin", version_prefix: "misultin" },
    HeaderSig { name: "Elli", category: "Web Server", header: "server", pattern: "elli", version_prefix: "" },
    HeaderSig { name: "Thin", category: "Web Server", header: "server", pattern: "thin", version_prefix: "thin" },
    HeaderSig { name: "Puma", category: "Web Server", header: "server", pattern: "puma", version_prefix: "puma" },
    HeaderSig { name: "Unicorn", category: "Web Server", header: "server", pattern: "unicorn", version_prefix: "" },
    HeaderSig { name: "Passenger", category: "Web Server", header: "server", pattern: "phusion passenger", version_prefix: "" },
    HeaderSig { name: "Passenger", category: "Web Server", header: "x-powered-by", pattern: "phusion passenger", version_prefix: "" },
    HeaderSig { name: "WEBrick", category: "Web Server", header: "server", pattern: "webrick", version_prefix: "webrick" },
    HeaderSig { name: "Falcon Ruby", category: "Web Server", header: "server", pattern: "falcon", version_prefix: "" },
    HeaderSig { name: "Iodine", category: "Web Server", header: "server", pattern: "iodine", version_prefix: "iodine" },
    HeaderSig { name: "Agoo", category: "Web Server", header: "server", pattern: "agoo", version_prefix: "agoo" },
    HeaderSig { name: "GWS", category: "Web Server", header: "server", pattern: "gws", version_prefix: "" },
    HeaderSig { name: "GSE", category: "Web Server", header: "server", pattern: "gse", version_prefix: "" },
    HeaderSig { name: "Kestrel", category: "Web Server", header: "server", pattern: "kestrel", version_prefix: "" },
    HeaderSig { name: "Werkzeug", category: "Web Server", header: "server", pattern: "werkzeug", version_prefix: "werkzeug" },
    HeaderSig { name: "Gunicorn", category: "Web Server", header: "server", pattern: "gunicorn", version_prefix: "gunicorn" },
    HeaderSig { name: "Uvicorn", category: "Web Server", header: "server", pattern: "uvicorn", version_prefix: "uvicorn" },
    HeaderSig { name: "Hypercorn", category: "Web Server", header: "server", pattern: "hypercorn", version_prefix: "hypercorn" },
    HeaderSig { name: "Daphne", category: "Web Server", header: "server", pattern: "daphne", version_prefix: "daphne" },
    HeaderSig { name: "Waitress", category: "Web Server", header: "server", pattern: "waitress", version_prefix: "waitress" },
    HeaderSig { name: "Bjoern", category: "Web Server", header: "server", pattern: "bjoern", version_prefix: "" },
    HeaderSig { name: "Meinheld", category: "Web Server", header: "server", pattern: "meinheld", version_prefix: "" },
    HeaderSig { name: "Twisted", category: "Web Server", header: "server", pattern: "twistedweb", version_prefix: "twistedweb" },
    HeaderSig { name: "CherryPy", category: "Web Server", header: "server", pattern: "cherrypy", version_prefix: "cherrypy" },
    HeaderSig { name: "SimpleHTTP", category: "Web Server", header: "server", pattern: "simplehttpserver", version_prefix: "" },
    HeaderSig { name: "BaseHTTP", category: "Web Server", header: "server", pattern: "basehttp", version_prefix: "" },
    HeaderSig { name: "Tornado", category: "Web Server", header: "server", pattern: "tornadoserver", version_prefix: "tornadoserver" },
    HeaderSig { name: "AIOHTTP", category: "Web Server", header: "server", pattern: "aiohttp", version_prefix: "" },
    HeaderSig { name: "Sanic", category: "Web Server", header: "server", pattern: "sanic", version_prefix: "" },

    // -- Embedded Web Server --
    HeaderSig { name: "GoAhead", category: "Embedded Web Server", header: "server", pattern: "goahead", version_prefix: "goahead" },
    HeaderSig { name: "Allegro RomPager", category: "Embedded Web Server", header: "server", pattern: "rompager", version_prefix: "rompager" },
    HeaderSig { name: "Embedthis Appweb", category: "Embedded Web Server", header: "server", pattern: "appweb", version_prefix: "appweb" },

    // -- Web Server --
    HeaderSig { name: "Oracle HTTP Server", category: "Web Server", header: "server", pattern: "oracle-http-server", version_prefix: "" },
    HeaderSig { name: "Oracle HTTP Server", category: "Web Server", header: "server", pattern: "oracle http server", version_prefix: "" },
    HeaderSig { name: "Sun ONE", category: "Web Server", header: "server", pattern: "sun-one", version_prefix: "" },
    HeaderSig { name: "iPlanet", category: "Web Server", header: "server", pattern: "iplanet", version_prefix: "" },
    HeaderSig { name: "IBM HTTP Server", category: "Web Server", header: "server", pattern: "ibm_http_server", version_prefix: "" },
    HeaderSig { name: "IBM HTTP Server", category: "Web Server", header: "server", pattern: "ibm http server", version_prefix: "" },
    HeaderSig { name: "Lotus Domino", category: "Web Server", header: "server", pattern: "lotus-domino", version_prefix: "lotus-domino" },
    HeaderSig { name: "Lotus Domino", category: "Web Server", header: "server", pattern: "domino", version_prefix: "" },
    HeaderSig { name: "WebSTAR", category: "Web Server", header: "server", pattern: "webstar", version_prefix: "webstar" },
    HeaderSig { name: "Xitami", category: "Web Server", header: "server", pattern: "xitami", version_prefix: "xitami" },
    HeaderSig { name: "Fnord", category: "Web Server", header: "server", pattern: "fnord", version_prefix: "" },
    HeaderSig { name: "KFWebServer", category: "Web Server", header: "server", pattern: "kfwebserver", version_prefix: "" },
    HeaderSig { name: "Savant", category: "Web Server", header: "server", pattern: "savant", version_prefix: "" },
    HeaderSig { name: "NetWare", category: "Web Server", header: "server", pattern: "netware", version_prefix: "" },

    // -- Embedded Web Server --
    HeaderSig { name: "RapidLogic", category: "Embedded Web Server", header: "server", pattern: "rapidlogic", version_prefix: "" },
    HeaderSig { name: "Mbedthis", category: "Embedded Web Server", header: "server", pattern: "mbedthis", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "WebStar", category: "Web Server", header: "server", pattern: "4d_webstar", version_prefix: "" },
    HeaderSig { name: "Zope", category: "Web Server", header: "server", pattern: "zope", version_prefix: "zope" },
    HeaderSig { name: "Medusa Server", category: "Web Server", header: "server", pattern: "medusa", version_prefix: "" },
    HeaderSig { name: "Snap", category: "Web Server", header: "server", pattern: "snap/", version_prefix: "" },
    HeaderSig { name: "Warp", category: "Web Server", header: "server", pattern: "warp", version_prefix: "" },
    HeaderSig { name: "Mighttpd", category: "Web Server", header: "server", pattern: "mighttpd", version_prefix: "mighttpd" },
    HeaderSig { name: "OpenLiteSpeed", category: "Web Server", header: "server", pattern: "openlitespeed", version_prefix: "openlitespeed" },

    // -- Proxy --
    HeaderSig { name: "Pingora", category: "Proxy", header: "server", pattern: "pingora", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Express", category: "Web Framework", header: "x-powered-by", pattern: "express", version_prefix: "" },
    HeaderSig { name: "Koa", category: "Web Framework", header: "x-powered-by", pattern: "koa", version_prefix: "" },
    HeaderSig { name: "Hapi", category: "Web Framework", header: "x-powered-by", pattern: "hapi", version_prefix: "" },
    HeaderSig { name: "Fastify", category: "Web Framework", header: "x-powered-by", pattern: "fastify", version_prefix: "" },
    HeaderSig { name: "NestJS", category: "Web Framework", header: "x-powered-by", pattern: "nestjs", version_prefix: "" },
    HeaderSig { name: "Sails.js", category: "Web Framework", header: "x-powered-by", pattern: "sails", version_prefix: "" },
    HeaderSig { name: "LoopBack", category: "Web Framework", header: "x-powered-by", pattern: "loopback", version_prefix: "" },
    HeaderSig { name: "Feathers", category: "Web Framework", header: "x-powered-by", pattern: "feathers", version_prefix: "" },
    HeaderSig { name: "AdonisJS", category: "Web Framework", header: "x-powered-by", pattern: "adonis", version_prefix: "" },
    HeaderSig { name: "Meteor", category: "Web Framework", header: "x-powered-by", pattern: "meteor", version_prefix: "" },
    HeaderSig { name: "Total.js", category: "Web Framework", header: "x-powered-by", pattern: "total.js", version_prefix: "" },
    HeaderSig { name: "Restify", category: "Web Framework", header: "server", pattern: "restify", version_prefix: "restify" },
    HeaderSig { name: "Restify", category: "Web Framework", header: "x-powered-by", pattern: "restify", version_prefix: "" },
    HeaderSig { name: "Polka", category: "Web Framework", header: "x-powered-by", pattern: "polka", version_prefix: "" },
    HeaderSig { name: "Micro", category: "Web Framework", header: "x-powered-by", pattern: "micro", version_prefix: "" },
    HeaderSig { name: "Moleculer", category: "Web Framework", header: "x-powered-by", pattern: "moleculer", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Strapi", category: "CMS", header: "x-powered-by", pattern: "strapi", version_prefix: "" },
    HeaderSig { name: "KeystoneJS", category: "CMS", header: "x-keystone-admin", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ghost", category: "CMS", header: "x-powered-by", pattern: "ghost", version_prefix: "" },
    HeaderSig { name: "Ghost", category: "CMS", header: "x-ghost-cache-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Directus", category: "CMS", header: "x-powered-by", pattern: "directus", version_prefix: "" },
    HeaderSig { name: "Payload CMS", category: "CMS", header: "x-powered-by", pattern: "payload", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Medusa Commerce", category: "eCommerce", header: "x-powered-by", pattern: "medusa", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "RedwoodJS", category: "Web Framework", header: "x-powered-by", pattern: "redwoodjs", version_prefix: "" },
    HeaderSig { name: "Remix", category: "Web Framework", header: "x-powered-by", pattern: "remix", version_prefix: "" },
    HeaderSig { name: "Nitro", category: "Web Framework", header: "x-powered-by", pattern: "nitro", version_prefix: "" },
    HeaderSig { name: "Nitro", category: "Web Framework", header: "server", pattern: "nitro", version_prefix: "" },
    HeaderSig { name: "Nuxt", category: "Web Framework", header: "x-powered-by", pattern: "nuxt", version_prefix: "" },
    HeaderSig { name: "Nuxt", category: "Web Framework", header: "x-nuxt-trace", pattern: "", version_prefix: "" },
    HeaderSig { name: "Next.js", category: "Web Framework", header: "x-powered-by", pattern: "next.js", version_prefix: "" },
    HeaderSig { name: "Next.js", category: "Web Framework", header: "x-nextjs-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Next.js", category: "Web Framework", header: "x-nextjs-matched-path", pattern: "", version_prefix: "" },

    // -- Static Site Generator --
    HeaderSig { name: "Gatsby", category: "Static Site Generator", header: "x-powered-by", pattern: "gatsby", version_prefix: "" },
    HeaderSig { name: "Gatsby", category: "Static Site Generator", header: "x-gatsby-cache", pattern: "", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Svelte", category: "Web Framework", header: "x-powered-by", pattern: "svelte", version_prefix: "" },
    HeaderSig { name: "SvelteKit", category: "Web Framework", header: "x-sveltekit-page", pattern: "", version_prefix: "" },
    HeaderSig { name: "Astro", category: "Web Framework", header: "x-astro-headers", pattern: "", version_prefix: "" },

    // -- Runtime --
    HeaderSig { name: "Deno", category: "Runtime", header: "server", pattern: "deno", version_prefix: "deno" },

    // -- PaaS --
    HeaderSig { name: "Deno Deploy", category: "PaaS", header: "server", pattern: "deno deploy", version_prefix: "" },

    // -- Runtime --
    HeaderSig { name: "Bun", category: "Runtime", header: "server", pattern: "bun", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Derby", category: "Web Framework", header: "x-powered-by", pattern: "derby", version_prefix: "" },
    HeaderSig { name: "Seneca", category: "Web Framework", header: "x-powered-by", pattern: "seneca", version_prefix: "" },
    HeaderSig { name: "Blitz.js", category: "Web Framework", header: "x-powered-by", pattern: "blitz", version_prefix: "" },
    HeaderSig { name: "Hono", category: "Web Framework", header: "x-powered-by", pattern: "hono", version_prefix: "" },
    HeaderSig { name: "Hono", category: "Web Framework", header: "server", pattern: "hono", version_prefix: "" },
    HeaderSig { name: "Elysia", category: "Web Framework", header: "x-powered-by", pattern: "elysia", version_prefix: "" },
    HeaderSig { name: "Django", category: "Web Framework", header: "x-powered-by", pattern: "django", version_prefix: "" },
    HeaderSig { name: "Django", category: "Web Framework", header: "server", pattern: "django", version_prefix: "" },
    HeaderSig { name: "Flask", category: "Web Framework", header: "x-powered-by", pattern: "flask", version_prefix: "" },
    HeaderSig { name: "FastAPI", category: "Web Framework", header: "server", pattern: "fastapi", version_prefix: "" },
    HeaderSig { name: "FastAPI", category: "Web Framework", header: "x-powered-by", pattern: "fastapi", version_prefix: "" },
    HeaderSig { name: "Bottle", category: "Web Framework", header: "server", pattern: "bottle", version_prefix: "bottle" },
    HeaderSig { name: "Pyramid", category: "Web Framework", header: "x-powered-by", pattern: "pyramid", version_prefix: "" },
    HeaderSig { name: "web2py", category: "Web Framework", header: "x-powered-by", pattern: "web2py", version_prefix: "" },
    HeaderSig { name: "Quart", category: "Web Framework", header: "server", pattern: "quart", version_prefix: "" },
    HeaderSig { name: "Starlette", category: "Web Framework", header: "server", pattern: "starlette", version_prefix: "" },
    HeaderSig { name: "Falcon", category: "Web Framework", header: "server", pattern: "falcon", version_prefix: "" },
    HeaderSig { name: "Falcon", category: "Web Framework", header: "x-powered-by", pattern: "falcon", version_prefix: "" },
    HeaderSig { name: "Hug", category: "Web Framework", header: "x-powered-by", pattern: "hug", version_prefix: "" },
    HeaderSig { name: "Masonite", category: "Web Framework", header: "x-powered-by", pattern: "masonite", version_prefix: "" },
    HeaderSig { name: "Litestar", category: "Web Framework", header: "server", pattern: "litestar", version_prefix: "" },
    HeaderSig { name: "Litestar", category: "Web Framework", header: "x-powered-by", pattern: "litestar", version_prefix: "" },
    HeaderSig { name: "Robyn", category: "Web Framework", header: "server", pattern: "robyn", version_prefix: "" },
    HeaderSig { name: "BlackSheep", category: "Web Framework", header: "server", pattern: "blacksheep", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Plone", category: "CMS", header: "x-powered-by", pattern: "plone", version_prefix: "" },
    HeaderSig { name: "Wagtail", category: "CMS", header: "x-wagtail-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Mezzanine", category: "CMS", header: "x-powered-by", pattern: "mezzanine", version_prefix: "" },
    HeaderSig { name: "django CMS", category: "CMS", header: "x-powered-by", pattern: "django-cms", version_prefix: "" },
    HeaderSig { name: "django CMS", category: "CMS", header: "x-django-cms", pattern: "", version_prefix: "" },
    HeaderSig { name: "Lektor", category: "CMS", header: "x-powered-by", pattern: "lektor", version_prefix: "" },

    // -- Static Site Generator --
    HeaderSig { name: "Pelican", category: "Static Site Generator", header: "x-powered-by", pattern: "pelican", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Laravel", category: "Web Framework", header: "x-powered-by", pattern: "laravel", version_prefix: "" },
    HeaderSig { name: "Laravel", category: "Web Framework", header: "set-cookie", pattern: "laravel_session", version_prefix: "" },
    HeaderSig { name: "Symfony", category: "Web Framework", header: "x-powered-by", pattern: "symfony", version_prefix: "" },
    HeaderSig { name: "Symfony", category: "Web Framework", header: "x-debug-token", pattern: "", version_prefix: "" },
    HeaderSig { name: "Symfony", category: "Web Framework", header: "x-debug-token-link", pattern: "", version_prefix: "" },
    HeaderSig { name: "CodeIgniter", category: "Web Framework", header: "x-powered-by", pattern: "codeigniter", version_prefix: "" },
    HeaderSig { name: "CodeIgniter", category: "Web Framework", header: "set-cookie", pattern: "ci_session", version_prefix: "" },
    HeaderSig { name: "CakePHP", category: "Web Framework", header: "x-powered-by", pattern: "cakephp", version_prefix: "" },
    HeaderSig { name: "CakePHP", category: "Web Framework", header: "set-cookie", pattern: "cakephp", version_prefix: "" },
    HeaderSig { name: "Yii", category: "Web Framework", header: "x-powered-by", pattern: "yii", version_prefix: "" },
    HeaderSig { name: "Yii", category: "Web Framework", header: "set-cookie", pattern: "yii_csrf", version_prefix: "" },
    HeaderSig { name: "Zend Framework", category: "Web Framework", header: "x-powered-by", pattern: "zend", version_prefix: "" },
    HeaderSig { name: "Laminas", category: "Web Framework", header: "x-powered-by", pattern: "laminas", version_prefix: "" },
    HeaderSig { name: "Slim", category: "Web Framework", header: "x-powered-by", pattern: "slim", version_prefix: "" },
    HeaderSig { name: "Lumen", category: "Web Framework", header: "x-powered-by", pattern: "lumen", version_prefix: "" },
    HeaderSig { name: "Phalcon", category: "Web Framework", header: "x-powered-by", pattern: "phalcon", version_prefix: "" },
    HeaderSig { name: "FuelPHP", category: "Web Framework", header: "x-powered-by", pattern: "fuelphp", version_prefix: "" },
    HeaderSig { name: "FuelPHP", category: "Web Framework", header: "set-cookie", pattern: "fuelcid", version_prefix: "" },
    HeaderSig { name: "Flight", category: "Web Framework", header: "x-powered-by", pattern: "flight", version_prefix: "" },
    HeaderSig { name: "Nette", category: "Web Framework", header: "x-powered-by", pattern: "nette", version_prefix: "" },
    HeaderSig { name: "Spiral", category: "Web Framework", header: "x-powered-by", pattern: "spiral", version_prefix: "" },
    HeaderSig { name: "Leaf PHP", category: "Web Framework", header: "x-powered-by", pattern: "leaf", version_prefix: "" },
    HeaderSig { name: "Hyperf", category: "Web Framework", header: "x-powered-by", pattern: "hyperf", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "Swoole", category: "Web Server", header: "server", pattern: "swoole", version_prefix: "swoole" },
    HeaderSig { name: "Swoole", category: "Web Server", header: "x-powered-by", pattern: "swoole", version_prefix: "" },
    HeaderSig { name: "RoadRunner", category: "Web Server", header: "x-powered-by", pattern: "roadrunner", version_prefix: "" },
    HeaderSig { name: "FrankenPHP", category: "Web Server", header: "server", pattern: "frankenphp", version_prefix: "" },
    HeaderSig { name: "ReactPHP", category: "Web Server", header: "x-powered-by", pattern: "reactphp", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "WordPress", category: "CMS", header: "x-powered-by", pattern: "wordpress", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "x-pingback", pattern: "xmlrpc.php", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "set-cookie", pattern: "wordpress_", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "set-cookie", pattern: "wp-settings", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "x-redirect-by", pattern: "wordpress", version_prefix: "" },
    HeaderSig { name: "WordPress", category: "CMS", header: "link", pattern: "wp-json", version_prefix: "" },
    HeaderSig { name: "Joomla", category: "CMS", header: "x-powered-by", pattern: "joomla", version_prefix: "" },
    HeaderSig { name: "Joomla", category: "CMS", header: "set-cookie", pattern: "joomla_", version_prefix: "" },
    HeaderSig { name: "Joomla", category: "CMS", header: "x-content-encoded-by", pattern: "joomla", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "x-drupal-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "x-drupal-dynamic-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "x-generator", pattern: "drupal", version_prefix: "" },
    HeaderSig { name: "Drupal", category: "CMS", header: "set-cookie", pattern: "drupal", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Magento", category: "eCommerce", header: "x-magento-vary", pattern: "", version_prefix: "" },
    HeaderSig { name: "Magento", category: "eCommerce", header: "x-magento-cache-control", pattern: "", version_prefix: "" },
    HeaderSig { name: "Magento", category: "eCommerce", header: "x-magento-cache-debug", pattern: "", version_prefix: "" },
    HeaderSig { name: "Magento", category: "eCommerce", header: "set-cookie", pattern: "mage-", version_prefix: "" },
    HeaderSig { name: "PrestaShop", category: "eCommerce", header: "x-powered-by", pattern: "prestashop", version_prefix: "" },
    HeaderSig { name: "PrestaShop", category: "eCommerce", header: "set-cookie", pattern: "prestashop", version_prefix: "" },
    HeaderSig { name: "OpenCart", category: "eCommerce", header: "set-cookie", pattern: "opencart", version_prefix: "" },
    HeaderSig { name: "WooCommerce", category: "eCommerce", header: "x-powered-by", pattern: "woocommerce", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "TYPO3", category: "CMS", header: "x-powered-by", pattern: "typo3", version_prefix: "" },
    HeaderSig { name: "TYPO3", category: "CMS", header: "x-typo3-parsetime", pattern: "", version_prefix: "" },
    HeaderSig { name: "TYPO3", category: "CMS", header: "set-cookie", pattern: "typo3", version_prefix: "" },
    HeaderSig { name: "Contao", category: "CMS", header: "x-powered-by", pattern: "contao", version_prefix: "" },
    HeaderSig { name: "Contao", category: "CMS", header: "x-contao-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Concrete5", category: "CMS", header: "x-powered-by", pattern: "concrete5", version_prefix: "" },
    HeaderSig { name: "SilverStripe", category: "CMS", header: "x-powered-by", pattern: "silverstripe", version_prefix: "" },
    HeaderSig { name: "SilverStripe", category: "CMS", header: "x-silverstripe-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Craft CMS", category: "CMS", header: "x-powered-by", pattern: "craft cms", version_prefix: "" },
    HeaderSig { name: "Craft CMS", category: "CMS", header: "x-craft-csrf", pattern: "", version_prefix: "" },
    HeaderSig { name: "October CMS", category: "CMS", header: "x-powered-by", pattern: "october", version_prefix: "" },
    HeaderSig { name: "October CMS", category: "CMS", header: "set-cookie", pattern: "october_session", version_prefix: "" },
    HeaderSig { name: "Statamic", category: "CMS", header: "x-powered-by", pattern: "statamic", version_prefix: "" },
    HeaderSig { name: "Kirby", category: "CMS", header: "x-powered-by", pattern: "kirby", version_prefix: "" },
    HeaderSig { name: "Grav", category: "CMS", header: "x-powered-by", pattern: "grav", version_prefix: "" },
    HeaderSig { name: "ProcessWire", category: "CMS", header: "x-powered-by", pattern: "processwire", version_prefix: "" },
    HeaderSig { name: "ExpressionEngine", category: "CMS", header: "x-powered-by", pattern: "expressionengine", version_prefix: "" },
    HeaderSig { name: "ExpressionEngine", category: "CMS", header: "set-cookie", pattern: "exp_tracker", version_prefix: "" },
    HeaderSig { name: "Textpattern", category: "CMS", header: "x-powered-by", pattern: "textpattern", version_prefix: "" },
    HeaderSig { name: "Serendipity", category: "CMS", header: "x-powered-by", pattern: "serendipity", version_prefix: "" },
    HeaderSig { name: "b2evolution", category: "CMS", header: "x-powered-by", pattern: "b2evolution", version_prefix: "" },
    HeaderSig { name: "Movable Type", category: "CMS", header: "x-powered-by", pattern: "movable type", version_prefix: "" },

    // -- Database Tool --
    HeaderSig { name: "PHPMyAdmin", category: "Database Tool", header: "x-powered-by", pattern: "phpmyadmin", version_prefix: "" },
    HeaderSig { name: "PHPMyAdmin", category: "Database Tool", header: "set-cookie", pattern: "phpmyadmin", version_prefix: "" },
    HeaderSig { name: "Adminer", category: "Database Tool", header: "x-powered-by", pattern: "adminer", version_prefix: "" },
    HeaderSig { name: "phpPgAdmin", category: "Database Tool", header: "x-powered-by", pattern: "phppgadmin", version_prefix: "" },

    // -- Webmail --
    HeaderSig { name: "Roundcube", category: "Webmail", header: "set-cookie", pattern: "roundcube", version_prefix: "" },
    HeaderSig { name: "SquirrelMail", category: "Webmail", header: "set-cookie", pattern: "squirrelmail", version_prefix: "" },
    HeaderSig { name: "Horde", category: "Webmail", header: "set-cookie", pattern: "horde_", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Ruby on Rails", category: "Web Framework", header: "x-powered-by", pattern: "rails", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Web Framework", header: "x-runtime", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Web Framework", header: "x-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ruby on Rails", category: "Web Framework", header: "set-cookie", pattern: "_rails_", version_prefix: "" },
    HeaderSig { name: "Sinatra", category: "Web Framework", header: "x-powered-by", pattern: "sinatra", version_prefix: "" },
    HeaderSig { name: "Sinatra", category: "Web Framework", header: "server", pattern: "sinatra", version_prefix: "" },
    HeaderSig { name: "Hanami", category: "Web Framework", header: "x-powered-by", pattern: "hanami", version_prefix: "" },
    HeaderSig { name: "Padrino", category: "Web Framework", header: "x-powered-by", pattern: "padrino", version_prefix: "" },
    HeaderSig { name: "Grape", category: "Web Framework", header: "x-powered-by", pattern: "grape", version_prefix: "" },
    HeaderSig { name: "Roda", category: "Web Framework", header: "x-powered-by", pattern: "roda", version_prefix: "" },
    HeaderSig { name: "Cuba", category: "Web Framework", header: "x-powered-by", pattern: "cuba", version_prefix: "" },
    HeaderSig { name: "Rack", category: "Web Framework", header: "x-powered-by", pattern: "rack", version_prefix: "" },
    HeaderSig { name: "Rack", category: "Web Framework", header: "server", pattern: "rack", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "Tomcat", category: "Web Server", header: "server", pattern: "apache-coyote", version_prefix: "apache-coyote" },
    HeaderSig { name: "Tomcat", category: "Web Server", header: "server", pattern: "tomcat", version_prefix: "tomcat" },
    HeaderSig { name: "Tomcat", category: "Web Server", header: "x-powered-by", pattern: "tomcat", version_prefix: "" },
    HeaderSig { name: "Jetty", category: "Web Server", header: "server", pattern: "jetty", version_prefix: "jetty" },
    HeaderSig { name: "Undertow", category: "Web Server", header: "server", pattern: "undertow", version_prefix: "" },

    // -- Application Server --
    HeaderSig { name: "GlassFish", category: "Application Server", header: "server", pattern: "glassfish", version_prefix: "glassfish" },
    HeaderSig { name: "GlassFish", category: "Application Server", header: "x-powered-by", pattern: "glassfish", version_prefix: "" },
    HeaderSig { name: "WildFly", category: "Application Server", header: "server", pattern: "wildfly", version_prefix: "wildfly" },
    HeaderSig { name: "WildFly", category: "Application Server", header: "x-powered-by", pattern: "wildfly", version_prefix: "" },
    HeaderSig { name: "JBoss", category: "Application Server", header: "server", pattern: "jboss", version_prefix: "" },
    HeaderSig { name: "JBoss", category: "Application Server", header: "x-powered-by", pattern: "jboss", version_prefix: "" },
    HeaderSig { name: "WebLogic", category: "Application Server", header: "server", pattern: "weblogic", version_prefix: "weblogic" },
    HeaderSig { name: "WebLogic", category: "Application Server", header: "x-powered-by", pattern: "weblogic", version_prefix: "" },
    HeaderSig { name: "WebSphere", category: "Application Server", header: "server", pattern: "websphere", version_prefix: "" },
    HeaderSig { name: "WebSphere", category: "Application Server", header: "x-powered-by", pattern: "websphere", version_prefix: "" },
    HeaderSig { name: "Payara", category: "Application Server", header: "server", pattern: "payara", version_prefix: "payara" },
    HeaderSig { name: "Payara", category: "Application Server", header: "x-powered-by", pattern: "payara", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Spring Boot", category: "Web Framework", header: "x-powered-by", pattern: "spring boot", version_prefix: "" },
    HeaderSig { name: "Spring Boot", category: "Web Framework", header: "x-application-context", pattern: "", version_prefix: "" },
    HeaderSig { name: "Spring MVC", category: "Web Framework", header: "x-powered-by", pattern: "spring", version_prefix: "" },
    HeaderSig { name: "Micronaut", category: "Web Framework", header: "server", pattern: "micronaut", version_prefix: "" },
    HeaderSig { name: "Micronaut", category: "Web Framework", header: "x-powered-by", pattern: "micronaut", version_prefix: "" },
    HeaderSig { name: "Quarkus", category: "Web Framework", header: "x-powered-by", pattern: "quarkus", version_prefix: "" },
    HeaderSig { name: "Vert.x", category: "Web Framework", header: "server", pattern: "vert.x", version_prefix: "" },
    HeaderSig { name: "Vert.x", category: "Web Framework", header: "x-powered-by", pattern: "vert.x", version_prefix: "" },
    HeaderSig { name: "Grails", category: "Web Framework", header: "x-powered-by", pattern: "grails", version_prefix: "" },
    HeaderSig { name: "Play Framework", category: "Web Framework", header: "x-powered-by", pattern: "play", version_prefix: "" },
    HeaderSig { name: "Vaadin", category: "Web Framework", header: "x-powered-by", pattern: "vaadin", version_prefix: "" },
    HeaderSig { name: "JSF", category: "Web Framework", header: "x-powered-by", pattern: "jsf", version_prefix: "" },
    HeaderSig { name: "Struts", category: "Web Framework", header: "x-powered-by", pattern: "struts", version_prefix: "" },
    HeaderSig { name: "Wicket", category: "Web Framework", header: "x-powered-by", pattern: "wicket", version_prefix: "" },
    HeaderSig { name: "Tapestry", category: "Web Framework", header: "x-powered-by", pattern: "tapestry", version_prefix: "" },
    HeaderSig { name: "Ratpack", category: "Web Framework", header: "server", pattern: "ratpack", version_prefix: "" },
    HeaderSig { name: "Spark Java", category: "Web Framework", header: "x-powered-by", pattern: "spark", version_prefix: "" },
    HeaderSig { name: "Javalin", category: "Web Framework", header: "server", pattern: "javalin", version_prefix: "" },
    HeaderSig { name: "Helidon", category: "Web Framework", header: "server", pattern: "helidon", version_prefix: "" },
    HeaderSig { name: "Dropwizard", category: "Web Framework", header: "server", pattern: "dropwizard", version_prefix: "" },

    // -- Java Platform --
    HeaderSig { name: "Liferay", category: "Java Platform", header: "x-powered-by", pattern: "liferay", version_prefix: "" },

    // -- Application Server --
    HeaderSig { name: "Resin", category: "Application Server", header: "server", pattern: "resin", version_prefix: "resin" },
    HeaderSig { name: "Resin", category: "Application Server", header: "x-powered-by", pattern: "resin", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Gin", category: "Web Framework", header: "x-powered-by", pattern: "gin", version_prefix: "" },
    HeaderSig { name: "Gin", category: "Web Framework", header: "server", pattern: "gin", version_prefix: "" },
    HeaderSig { name: "Echo", category: "Web Framework", header: "x-powered-by", pattern: "echo", version_prefix: "" },
    HeaderSig { name: "Fiber", category: "Web Framework", header: "x-powered-by", pattern: "fiber", version_prefix: "" },
    HeaderSig { name: "Fiber", category: "Web Framework", header: "server", pattern: "fiber", version_prefix: "" },
    HeaderSig { name: "Chi", category: "Web Framework", header: "x-powered-by", pattern: "chi", version_prefix: "" },
    HeaderSig { name: "Buffalo", category: "Web Framework", header: "x-powered-by", pattern: "buffalo", version_prefix: "" },
    HeaderSig { name: "Revel", category: "Web Framework", header: "x-powered-by", pattern: "revel", version_prefix: "" },
    HeaderSig { name: "Beego", category: "Web Framework", header: "server", pattern: "beego", version_prefix: "" },
    HeaderSig { name: "Beego", category: "Web Framework", header: "x-powered-by", pattern: "beego", version_prefix: "" },
    HeaderSig { name: "Iris", category: "Web Framework", header: "x-powered-by", pattern: "iris", version_prefix: "" },
    HeaderSig { name: "Martini", category: "Web Framework", header: "x-powered-by", pattern: "martini", version_prefix: "" },

    // -- Static Site Generator --
    HeaderSig { name: "Hugo", category: "Static Site Generator", header: "x-powered-by", pattern: "hugo", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Gorilla Mux", category: "Web Framework", header: "x-powered-by", pattern: "gorilla", version_prefix: "" },
    HeaderSig { name: "Actix-web", category: "Web Framework", header: "server", pattern: "actix-web", version_prefix: "" },
    HeaderSig { name: "Actix-web", category: "Web Framework", header: "x-powered-by", pattern: "actix", version_prefix: "" },
    HeaderSig { name: "Axum", category: "Web Framework", header: "server", pattern: "axum", version_prefix: "" },
    HeaderSig { name: "Rocket", category: "Web Framework", header: "server", pattern: "rocket", version_prefix: "rocket" },
    HeaderSig { name: "Warp Rust", category: "Web Framework", header: "server", pattern: "warp", version_prefix: "" },
    HeaderSig { name: "Tide", category: "Web Framework", header: "server", pattern: "tide", version_prefix: "" },
    HeaderSig { name: "Gotham", category: "Web Framework", header: "server", pattern: "gotham", version_prefix: "" },
    HeaderSig { name: "Nickel", category: "Web Framework", header: "server", pattern: "nickel", version_prefix: "" },
    HeaderSig { name: "Iron", category: "Web Framework", header: "server", pattern: "iron", version_prefix: "" },
    HeaderSig { name: "Poem", category: "Web Framework", header: "server", pattern: "poem", version_prefix: "" },
    HeaderSig { name: "Salvo", category: "Web Framework", header: "server", pattern: "salvo", version_prefix: "" },
    HeaderSig { name: "ASP.NET", category: "Web Framework", header: "x-powered-by", pattern: "asp.net", version_prefix: "" },
    HeaderSig { name: "ASP.NET", category: "Web Framework", header: "x-aspnet-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "ASP.NET MVC", category: "Web Framework", header: "x-aspnetmvc-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Blazor", category: "Web Framework", header: "x-powered-by", pattern: "blazor", version_prefix: "" },
    HeaderSig { name: "Nancy", category: "Web Framework", header: "x-powered-by", pattern: "nancy", version_prefix: "" },
    HeaderSig { name: "ServiceStack", category: "Web Framework", header: "x-powered-by", pattern: "servicestack", version_prefix: "" },
    HeaderSig { name: "Carter", category: "Web Framework", header: "x-powered-by", pattern: "carter", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "DotNetNuke", category: "CMS", header: "x-powered-by", pattern: "dotnetnuke", version_prefix: "" },
    HeaderSig { name: "DotNetNuke", category: "CMS", header: "set-cookie", pattern: "dotnetnuke", version_prefix: "" },
    HeaderSig { name: "DotNetNuke", category: "CMS", header: "set-cookie", pattern: "dnn_", version_prefix: "" },
    HeaderSig { name: "Umbraco", category: "CMS", header: "x-powered-by", pattern: "umbraco", version_prefix: "" },
    HeaderSig { name: "Umbraco", category: "CMS", header: "x-umbraco-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Sitecore", category: "CMS", header: "x-powered-by", pattern: "sitecore", version_prefix: "" },
    HeaderSig { name: "Sitecore", category: "CMS", header: "set-cookie", pattern: "sc_analytics", version_prefix: "" },
    HeaderSig { name: "Sitecore", category: "CMS", header: "x-sitecore-server", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kentico", category: "CMS", header: "x-powered-by", pattern: "kentico", version_prefix: "" },
    HeaderSig { name: "Kentico", category: "CMS", header: "set-cookie", pattern: "kentico", version_prefix: "" },
    HeaderSig { name: "Episerver", category: "CMS", header: "x-powered-by", pattern: "episerver", version_prefix: "" },
    HeaderSig { name: "Optimizely", category: "CMS", header: "x-powered-by", pattern: "optimizely", version_prefix: "" },
    HeaderSig { name: "Orchard", category: "CMS", header: "x-powered-by", pattern: "orchard", version_prefix: "" },
    HeaderSig { name: "Sitefinity", category: "CMS", header: "x-powered-by", pattern: "sitefinity", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "nopCommerce", category: "eCommerce", header: "x-powered-by", pattern: "nopcommerce", version_prefix: "" },
    HeaderSig { name: "nopCommerce", category: "eCommerce", header: "set-cookie", pattern: "nop.customer", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Phoenix", category: "Web Framework", header: "x-powered-by", pattern: "phoenix", version_prefix: "" },
    HeaderSig { name: "Phoenix", category: "Web Framework", header: "server", pattern: "phoenix", version_prefix: "" },
    HeaderSig { name: "Phoenix", category: "Web Framework", header: "set-cookie", pattern: "_phoenix", version_prefix: "" },
    HeaderSig { name: "Plug", category: "Web Framework", header: "server", pattern: "plug", version_prefix: "" },
    HeaderSig { name: "Akka HTTP", category: "Web Framework", header: "server", pattern: "akka-http", version_prefix: "akka-http" },
    HeaderSig { name: "http4s", category: "Web Framework", header: "server", pattern: "http4s", version_prefix: "" },
    HeaderSig { name: "Finatra", category: "Web Framework", header: "server", pattern: "finatra", version_prefix: "" },
    HeaderSig { name: "Scalatra", category: "Web Framework", header: "x-powered-by", pattern: "scalatra", version_prefix: "" },
    HeaderSig { name: "Lift", category: "Web Framework", header: "x-lift-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ktor", category: "Web Framework", header: "server", pattern: "ktor", version_prefix: "ktor" },
    HeaderSig { name: "http4k", category: "Web Framework", header: "server", pattern: "http4k", version_prefix: "" },
    HeaderSig { name: "Vapor", category: "Web Framework", header: "server", pattern: "vapor", version_prefix: "" },
    HeaderSig { name: "Vapor", category: "Web Framework", header: "x-powered-by", pattern: "vapor", version_prefix: "" },
    HeaderSig { name: "Kitura", category: "Web Framework", header: "server", pattern: "kitura", version_prefix: "kitura" },
    HeaderSig { name: "Kitura", category: "Web Framework", header: "x-powered-by", pattern: "kitura", version_prefix: "" },
    HeaderSig { name: "Perfect", category: "Web Framework", header: "server", pattern: "perfect", version_prefix: "" },
    HeaderSig { name: "Yesod", category: "Web Framework", header: "x-powered-by", pattern: "yesod", version_prefix: "" },
    HeaderSig { name: "Scotty", category: "Web Framework", header: "server", pattern: "scotty", version_prefix: "" },
    HeaderSig { name: "Snap Framework", category: "Web Framework", header: "server", pattern: "snap", version_prefix: "snap" },
    HeaderSig { name: "Happstack", category: "Web Framework", header: "server", pattern: "happstack", version_prefix: "" },
    HeaderSig { name: "Servant", category: "Web Framework", header: "server", pattern: "servant", version_prefix: "" },
    HeaderSig { name: "Lapis", category: "Web Framework", header: "x-powered-by", pattern: "lapis", version_prefix: "" },
    HeaderSig { name: "Sailor", category: "Web Framework", header: "x-powered-by", pattern: "sailor", version_prefix: "" },
    HeaderSig { name: "Lor", category: "Web Framework", header: "x-powered-by", pattern: "lor", version_prefix: "" },
    HeaderSig { name: "Vanilla", category: "Web Framework", header: "x-powered-by", pattern: "vanilla", version_prefix: "" },
    HeaderSig { name: "Ring", category: "Web Framework", header: "x-powered-by", pattern: "ring", version_prefix: "" },
    HeaderSig { name: "Compojure", category: "Web Framework", header: "x-powered-by", pattern: "compojure", version_prefix: "" },
    HeaderSig { name: "Luminus", category: "Web Framework", header: "x-powered-by", pattern: "luminus", version_prefix: "" },
    HeaderSig { name: "Pedestal", category: "Web Framework", header: "x-powered-by", pattern: "pedestal", version_prefix: "" },
    HeaderSig { name: "Aleph", category: "Web Framework", header: "server", pattern: "aleph", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "CouchDB", category: "Database", header: "server", pattern: "couchdb", version_prefix: "couchdb" },
    HeaderSig { name: "CouchDB", category: "Database", header: "x-couchdb-body-time", pattern: "", version_prefix: "" },
    HeaderSig { name: "CouchDB", category: "Database", header: "x-couch-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "RethinkDB", category: "Database", header: "server", pattern: "rethinkdb", version_prefix: "" },
    HeaderSig { name: "ArangoDB", category: "Database", header: "server", pattern: "arangodb", version_prefix: "arangodb" },
    HeaderSig { name: "ArangoDB", category: "Database", header: "x-arango-errors", pattern: "", version_prefix: "" },
    HeaderSig { name: "ArangoDB", category: "Database", header: "x-arango-queue-time-seconds", pattern: "", version_prefix: "" },
    HeaderSig { name: "OrientDB", category: "Database", header: "server", pattern: "orientdb", version_prefix: "" },
    HeaderSig { name: "RavenDB", category: "Database", header: "server", pattern: "ravendb", version_prefix: "" },
    HeaderSig { name: "RavenDB", category: "Database", header: "raven-server-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "ClickHouse", category: "Database", header: "x-clickhouse-server-display-name", pattern: "", version_prefix: "" },
    HeaderSig { name: "ClickHouse", category: "Database", header: "x-clickhouse-query-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "ClickHouse", category: "Database", header: "x-clickhouse-format", pattern: "", version_prefix: "" },
    HeaderSig { name: "ClickHouse", category: "Database", header: "x-clickhouse-timezone", pattern: "", version_prefix: "" },

    // -- Search Engine --
    HeaderSig { name: "Elasticsearch", category: "Search Engine", header: "x-elastic-product", pattern: "elasticsearch", version_prefix: "" },
    HeaderSig { name: "Elasticsearch", category: "Search Engine", header: "server", pattern: "elasticsearch", version_prefix: "" },

    // -- Analytics --
    HeaderSig { name: "Kibana", category: "Analytics", header: "kbn-name", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kibana", category: "Analytics", header: "kbn-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kibana", category: "Analytics", header: "kbn-license-sig", pattern: "", version_prefix: "" },

    // -- Search Engine --
    HeaderSig { name: "Solr", category: "Search Engine", header: "server", pattern: "solr", version_prefix: "" },
    HeaderSig { name: "Meilisearch", category: "Search Engine", header: "server", pattern: "meilisearch", version_prefix: "" },
    HeaderSig { name: "Meilisearch", category: "Search Engine", header: "x-meilisearch-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Typesense", category: "Search Engine", header: "server", pattern: "typesense", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Grafana", category: "Monitoring", header: "x-grafana-org-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Grafana", category: "Monitoring", header: "server", pattern: "grafana", version_prefix: "" },
    HeaderSig { name: "Grafana", category: "Monitoring", header: "x-grafana-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Prometheus", category: "Monitoring", header: "server", pattern: "prometheus", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "InfluxDB", category: "Database", header: "x-influxdb-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "InfluxDB", category: "Database", header: "x-influxdb-build", pattern: "", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Victoria Metrics", category: "Monitoring", header: "server", pattern: "victoriametrics", version_prefix: "" },
    HeaderSig { name: "Thanos", category: "Monitoring", header: "server", pattern: "thanos", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "QuestDB", category: "Database", header: "server", pattern: "questdb", version_prefix: "" },
    HeaderSig { name: "DuckDB", category: "Database", header: "server", pattern: "duckdb", version_prefix: "" },
    HeaderSig { name: "TiDB", category: "Database", header: "server", pattern: "tidb", version_prefix: "" },
    HeaderSig { name: "ScyllaDB", category: "Database", header: "server", pattern: "scylladb", version_prefix: "" },
    HeaderSig { name: "SingleStore", category: "Database", header: "server", pattern: "singlestore", version_prefix: "" },
    HeaderSig { name: "Redis", category: "Database", header: "server", pattern: "redis", version_prefix: "" },

    // -- Database Tool --
    HeaderSig { name: "RedisInsight", category: "Database Tool", header: "server", pattern: "redisinsight", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "Cassandra", category: "Database", header: "server", pattern: "cassandra", version_prefix: "" },
    HeaderSig { name: "Neo4j", category: "Database", header: "server", pattern: "neo4j", version_prefix: "" },
    HeaderSig { name: "DGraph", category: "Database", header: "server", pattern: "dgraph", version_prefix: "" },
    HeaderSig { name: "SurrealDB", category: "Database", header: "server", pattern: "surrealdb", version_prefix: "" },
    HeaderSig { name: "FaunaDB", category: "Database", header: "x-faunadb-build", pattern: "", version_prefix: "" },
    HeaderSig { name: "PlanetScale", category: "Database", header: "x-planetscale-request-id", pattern: "", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Supabase", category: "PaaS", header: "x-supabase-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Supabase", category: "PaaS", header: "x-supabase-request-id", pattern: "", version_prefix: "" },

    // -- GraphQL --
    HeaderSig { name: "Hasura", category: "GraphQL", header: "x-hasura-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hasura", category: "GraphQL", header: "x-hasura-role", pattern: "", version_prefix: "" },

    // -- API Gateway --
    HeaderSig { name: "Kong", category: "API Gateway", header: "server", pattern: "kong", version_prefix: "kong" },
    HeaderSig { name: "Kong", category: "API Gateway", header: "via", pattern: "kong", version_prefix: "" },
    HeaderSig { name: "Kong", category: "API Gateway", header: "x-kong-upstream-latency", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kong", category: "API Gateway", header: "x-kong-proxy-latency", pattern: "", version_prefix: "" },
    HeaderSig { name: "Tyk", category: "API Gateway", header: "x-tyk-authorization", pattern: "", version_prefix: "" },
    HeaderSig { name: "Tyk", category: "API Gateway", header: "server", pattern: "tyk", version_prefix: "" },
    HeaderSig { name: "Apigee", category: "API Gateway", header: "x-apigee-proxy", pattern: "", version_prefix: "" },
    HeaderSig { name: "Apigee", category: "API Gateway", header: "server", pattern: "apigee", version_prefix: "" },
    HeaderSig { name: "AWS API Gateway", category: "API Gateway", header: "x-amzn-requestid", pattern: "", version_prefix: "" },
    HeaderSig { name: "AWS API Gateway", category: "API Gateway", header: "x-amz-apigw-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Azure API Management", category: "API Gateway", header: "ocp-apim-trace-location", pattern: "", version_prefix: "" },
    HeaderSig { name: "MuleSoft", category: "API Gateway", header: "x-powered-by", pattern: "mulesoft", version_prefix: "" },
    HeaderSig { name: "MuleSoft", category: "API Gateway", header: "server", pattern: "mule", version_prefix: "" },

    // -- Service Mesh --
    HeaderSig { name: "Istio Envoy", category: "Service Mesh", header: "server", pattern: "istio-envoy", version_prefix: "" },
    HeaderSig { name: "Istio Envoy", category: "Service Mesh", header: "x-envoy-upstream-service-time", pattern: "", version_prefix: "" },
    HeaderSig { name: "Istio Envoy", category: "Service Mesh", header: "x-envoy-decorator-operation", pattern: "", version_prefix: "" },

    // -- Proxy --
    HeaderSig { name: "Envoy", category: "Proxy", header: "server", pattern: "envoy", version_prefix: "" },

    // -- Service Mesh --
    HeaderSig { name: "Linkerd", category: "Service Mesh", header: "l5d-success-class", pattern: "", version_prefix: "" },
    HeaderSig { name: "Linkerd", category: "Service Mesh", header: "l5d-server-id", pattern: "", version_prefix: "" },

    // -- API Gateway --
    HeaderSig { name: "Ambassador", category: "API Gateway", header: "x-ambassador-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Gloo Edge", category: "API Gateway", header: "server", pattern: "gloo", version_prefix: "" },
    HeaderSig { name: "KrakenD", category: "API Gateway", header: "server", pattern: "krakend", version_prefix: "krakend" },
    HeaderSig { name: "KrakenD", category: "API Gateway", header: "x-krakend", pattern: "", version_prefix: "" },
    HeaderSig { name: "Gravitee", category: "API Gateway", header: "x-gravitee-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Gravitee", category: "API Gateway", header: "x-gravitee-transaction-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "WSO2", category: "API Gateway", header: "server", pattern: "wso2", version_prefix: "" },
    HeaderSig { name: "WSO2", category: "API Gateway", header: "x-wso2-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "APISIX", category: "API Gateway", header: "server", pattern: "apisix", version_prefix: "apisix" },
    HeaderSig { name: "APISIX", category: "API Gateway", header: "x-apisix-upstream-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Zuul", category: "API Gateway", header: "x-zuul", pattern: "", version_prefix: "" },
    HeaderSig { name: "Spring Cloud Gateway", category: "API Gateway", header: "x-powered-by", pattern: "spring cloud gateway", version_prefix: "" },

    // -- CI/CD --
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "x-jenkins", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "x-hudson", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "x-jenkins-session", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jenkins", category: "CI/CD", header: "server", pattern: "jenkins", version_prefix: "" },
    HeaderSig { name: "GitLab", category: "CI/CD", header: "x-gitlab-meta", pattern: "", version_prefix: "" },
    HeaderSig { name: "GitLab", category: "CI/CD", header: "set-cookie", pattern: "_gitlab_session", version_prefix: "" },
    HeaderSig { name: "Bamboo", category: "CI/CD", header: "x-powered-by", pattern: "bamboo", version_prefix: "" },
    HeaderSig { name: "TeamCity", category: "CI/CD", header: "server", pattern: "teamcity", version_prefix: "" },
    HeaderSig { name: "TeamCity", category: "CI/CD", header: "x-teamcity-node-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Drone", category: "CI/CD", header: "server", pattern: "drone", version_prefix: "" },
    HeaderSig { name: "Concourse", category: "CI/CD", header: "server", pattern: "concourse", version_prefix: "" },
    HeaderSig { name: "Argo CD", category: "CI/CD", header: "server", pattern: "argocd", version_prefix: "" },
    HeaderSig { name: "Spinnaker", category: "CI/CD", header: "server", pattern: "spinnaker", version_prefix: "" },

    // -- Container Registry --
    HeaderSig { name: "Harbor", category: "Container Registry", header: "server", pattern: "harbor", version_prefix: "" },
    HeaderSig { name: "Harbor", category: "Container Registry", header: "x-harbor-csrf-token", pattern: "", version_prefix: "" },

    // -- Artifact Repository --
    HeaderSig { name: "Nexus", category: "Artifact Repository", header: "server", pattern: "nexus", version_prefix: "nexus" },
    HeaderSig { name: "Nexus", category: "Artifact Repository", header: "x-nexus-ui", pattern: "", version_prefix: "" },
    HeaderSig { name: "Artifactory", category: "Artifact Repository", header: "server", pattern: "artifactory", version_prefix: "" },
    HeaderSig { name: "Artifactory", category: "Artifact Repository", header: "x-artifactory-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Verdaccio", category: "Artifact Repository", header: "server", pattern: "verdaccio", version_prefix: "" },
    HeaderSig { name: "Verdaccio", category: "Artifact Repository", header: "x-powered-by", pattern: "verdaccio", version_prefix: "" },

    // -- Version Control --
    HeaderSig { name: "Gitea", category: "Version Control", header: "server", pattern: "gitea", version_prefix: "" },
    HeaderSig { name: "Gitea", category: "Version Control", header: "set-cookie", pattern: "i_like_gitea", version_prefix: "" },
    HeaderSig { name: "Gogs", category: "Version Control", header: "set-cookie", pattern: "i_like_gogs", version_prefix: "" },
    HeaderSig { name: "Bitbucket", category: "Version Control", header: "x-powered-by", pattern: "bitbucket", version_prefix: "" },
    HeaderSig { name: "Gerrit", category: "Version Control", header: "x-gerrit-auth", pattern: "", version_prefix: "" },

    // -- Code Quality --
    HeaderSig { name: "SonarQube", category: "Code Quality", header: "server", pattern: "sonarqube", version_prefix: "" },
    HeaderSig { name: "SonarQube", category: "Code Quality", header: "x-sonarqube-version", pattern: "", version_prefix: "" },

    // -- Automation --
    HeaderSig { name: "Ansible AWX", category: "Automation", header: "server", pattern: "awx", version_prefix: "" },

    // -- IaC --
    HeaderSig { name: "Terraform Cloud", category: "IaC", header: "x-powered-by", pattern: "terraform", version_prefix: "" },

    // -- Version Control --
    HeaderSig { name: "Forgejo", category: "Version Control", header: "server", pattern: "forgejo", version_prefix: "" },
    HeaderSig { name: "Forgejo", category: "Version Control", header: "set-cookie", pattern: "i_like_forgejo", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Prometheus", category: "Monitoring", header: "x-prometheus-remote-write-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jaeger", category: "Monitoring", header: "server", pattern: "jaeger", version_prefix: "" },
    HeaderSig { name: "Zipkin", category: "Monitoring", header: "server", pattern: "zipkin", version_prefix: "" },

    // -- Error Tracking --
    HeaderSig { name: "Sentry", category: "Error Tracking", header: "x-sentry-rate-limits", pattern: "", version_prefix: "" },
    HeaderSig { name: "Sentry", category: "Error Tracking", header: "x-sentry-error", pattern: "", version_prefix: "" },
    HeaderSig { name: "Rollbar", category: "Error Tracking", header: "x-rollbar-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Bugsnag", category: "Error Tracking", header: "x-bugsnag-sent-at", pattern: "", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Datadog", category: "Monitoring", header: "x-datadog-trace-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Datadog", category: "Monitoring", header: "x-datadog-parent-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "New Relic", category: "Monitoring", header: "x-newrelic-app-data", pattern: "", version_prefix: "" },
    HeaderSig { name: "New Relic", category: "Monitoring", header: "x-newrelic-transaction", pattern: "", version_prefix: "" },
    HeaderSig { name: "Dynatrace", category: "Monitoring", header: "x-dynatrace", pattern: "", version_prefix: "" },
    HeaderSig { name: "Dynatrace", category: "Monitoring", header: "server-timing", pattern: "dtrpid", version_prefix: "" },
    HeaderSig { name: "Elastic APM", category: "Monitoring", header: "x-elastic-apm-traceparent", pattern: "", version_prefix: "" },

    // -- Log Management --
    HeaderSig { name: "Graylog", category: "Log Management", header: "x-graylog-node-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Seq", category: "Log Management", header: "server", pattern: "seq", version_prefix: "" },
    HeaderSig { name: "Splunk", category: "Log Management", header: "x-splunk-server", pattern: "", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Zabbix", category: "Monitoring", header: "server", pattern: "zabbix", version_prefix: "" },
    HeaderSig { name: "Nagios", category: "Monitoring", header: "server", pattern: "nagios", version_prefix: "" },
    HeaderSig { name: "Icinga", category: "Monitoring", header: "server", pattern: "icinga", version_prefix: "" },
    HeaderSig { name: "Checkmk", category: "Monitoring", header: "server", pattern: "check_mk", version_prefix: "" },
    HeaderSig { name: "PRTG", category: "Monitoring", header: "server", pattern: "prtg", version_prefix: "" },
    HeaderSig { name: "Netdata", category: "Monitoring", header: "server", pattern: "netdata", version_prefix: "" },
    HeaderSig { name: "Uptime Kuma", category: "Monitoring", header: "server", pattern: "uptime-kuma", version_prefix: "" },
    HeaderSig { name: "Cacti", category: "Monitoring", header: "set-cookie", pattern: "cacti_", version_prefix: "" },

    // -- Log Management --
    HeaderSig { name: "Loki", category: "Log Management", header: "server", pattern: "loki", version_prefix: "" },

    // -- Alerting --
    HeaderSig { name: "PagerDuty", category: "Alerting", header: "x-pagerduty-request-id", pattern: "", version_prefix: "" },

    // -- Error Tracking --
    HeaderSig { name: "Airbrake", category: "Error Tracking", header: "x-airbrake-request-id", pattern: "", version_prefix: "" },

    // -- Status --
    HeaderSig { name: "StatusPage", category: "Status", header: "x-statuspage-version", pattern: "", version_prefix: "" },

    // -- CDN/WAF --
    HeaderSig { name: "Cloudflare", category: "CDN/WAF", header: "cf-ray", pattern: "", version_prefix: "" },
    HeaderSig { name: "Cloudflare", category: "CDN/WAF", header: "cf-cache-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Cloudflare", category: "CDN/WAF", header: "server", pattern: "cloudflare", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN/WAF", header: "x-akamai-transformed", pattern: "", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN/WAF", header: "x-akamai-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Akamai", category: "CDN/WAF", header: "server", pattern: "akamaighost", version_prefix: "" },

    // -- WAF --
    HeaderSig { name: "Imperva", category: "WAF", header: "x-iinfo", pattern: "", version_prefix: "" },
    HeaderSig { name: "Imperva", category: "WAF", header: "x-cdn", pattern: "imperva", version_prefix: "" },
    HeaderSig { name: "Incapsula", category: "WAF", header: "set-cookie", pattern: "visid_incap_", version_prefix: "" },
    HeaderSig { name: "Incapsula", category: "WAF", header: "set-cookie", pattern: "incap_ses_", version_prefix: "" },
    HeaderSig { name: "Sucuri", category: "WAF", header: "x-sucuri-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Sucuri", category: "WAF", header: "server", pattern: "sucuri", version_prefix: "" },
    HeaderSig { name: "Sucuri", category: "WAF", header: "x-sucuri-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "AWS WAF", category: "WAF", header: "x-amzn-waf-action", pattern: "", version_prefix: "" },
    HeaderSig { name: "Azure WAF", category: "WAF", header: "x-azure-ref", pattern: "", version_prefix: "" },
    HeaderSig { name: "ModSecurity", category: "WAF", header: "server", pattern: "mod_security", version_prefix: "" },
    HeaderSig { name: "ModSecurity", category: "WAF", header: "x-modsecurity-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Barracuda", category: "WAF", header: "server", pattern: "barracuda", version_prefix: "" },
    HeaderSig { name: "Barracuda", category: "WAF", header: "x-barracuda-waf", pattern: "", version_prefix: "" },
    HeaderSig { name: "Fortinet FortiWeb", category: "WAF", header: "server", pattern: "fortiweb", version_prefix: "" },
    HeaderSig { name: "Citrix ADC", category: "WAF", header: "via", pattern: "ns-cache", version_prefix: "" },
    HeaderSig { name: "Citrix ADC", category: "WAF", header: "set-cookie", pattern: "nsconn", version_prefix: "" },
    HeaderSig { name: "F5 BIG-IP", category: "WAF", header: "server", pattern: "big-ip", version_prefix: "" },
    HeaderSig { name: "F5 BIG-IP", category: "WAF", header: "set-cookie", pattern: "bigipserver", version_prefix: "" },
    HeaderSig { name: "Signal Sciences", category: "WAF", header: "x-sigsci-decision-ms", pattern: "", version_prefix: "" },
    HeaderSig { name: "Signal Sciences", category: "WAF", header: "x-sigsci-tags", pattern: "", version_prefix: "" },

    // -- Auth --
    HeaderSig { name: "Keycloak", category: "Auth", header: "server", pattern: "keycloak", version_prefix: "" },
    HeaderSig { name: "Keycloak", category: "Auth", header: "set-cookie", pattern: "keycloak_", version_prefix: "" },
    HeaderSig { name: "Auth0", category: "Auth", header: "x-auth0-requestid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Okta", category: "Auth", header: "x-okta-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Okta", category: "Auth", header: "set-cookie", pattern: "okta-oauth-state", version_prefix: "" },
    HeaderSig { name: "OneLogin", category: "Auth", header: "x-onelogin-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Duo Security", category: "Auth", header: "x-powered-by", pattern: "duo", version_prefix: "" },

    // -- CDN/WAF --
    HeaderSig { name: "DDoS-Guard", category: "CDN/WAF", header: "server", pattern: "ddos-guard", version_prefix: "" },

    // -- WAF --
    HeaderSig { name: "Wallarm", category: "WAF", header: "server", pattern: "wallarm", version_prefix: "" },
    HeaderSig { name: "Wordfence", category: "WAF", header: "x-wordfence-blocked", pattern: "", version_prefix: "" },

    // -- CDN/WAF --
    HeaderSig { name: "StackPath", category: "CDN/WAF", header: "server", pattern: "stackpath", version_prefix: "" },

    // -- WAF --
    HeaderSig { name: "Reblaze", category: "WAF", header: "x-reblaze-protection", pattern: "", version_prefix: "" },

    // -- Security --
    HeaderSig { name: "CrowdStrike", category: "Security", header: "x-crowdstrike-request-id", pattern: "", version_prefix: "" },

    // -- Firewall --
    HeaderSig { name: "pfSense", category: "Firewall", header: "server", pattern: "pfsense", version_prefix: "" },
    HeaderSig { name: "OPNsense", category: "Firewall", header: "server", pattern: "opnsense", version_prefix: "" },
    HeaderSig { name: "Sophos", category: "Firewall", header: "server", pattern: "sophos", version_prefix: "" },

    // -- Router --
    HeaderSig { name: "Mikrotik", category: "Router", header: "server", pattern: "mikrotik", version_prefix: "" },
    HeaderSig { name: "Ubiquiti UniFi", category: "Router", header: "x-unifi-request-id", pattern: "", version_prefix: "" },

    // -- Auth --
    HeaderSig { name: "Authentik", category: "Auth", header: "x-authentik-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Authelia", category: "Auth", header: "server", pattern: "authelia", version_prefix: "" },
    HeaderSig { name: "Zitadel", category: "Auth", header: "x-zitadel-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "FusionAuth", category: "Auth", header: "x-fusionauth-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hydra", category: "Auth", header: "server", pattern: "hydra", version_prefix: "" },
    HeaderSig { name: "Kratos", category: "Auth", header: "x-kratos-session", pattern: "", version_prefix: "" },
    HeaderSig { name: "SuperTokens", category: "Auth", header: "x-supertokens-rid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Clerk", category: "Auth", header: "x-clerk-auth-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "NextAuth.js", category: "Auth", header: "set-cookie", pattern: "next-auth", version_prefix: "" },

    // -- CDN --
    HeaderSig { name: "Fastly", category: "CDN", header: "x-fastly-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Fastly", category: "CDN", header: "via", pattern: "varnish", version_prefix: "" },
    HeaderSig { name: "Fastly", category: "CDN", header: "x-served-by", pattern: "cache-", version_prefix: "" },
    HeaderSig { name: "KeyCDN", category: "CDN", header: "server", pattern: "keycdn", version_prefix: "" },
    HeaderSig { name: "BunnyCDN", category: "CDN", header: "server", pattern: "bunnycdn", version_prefix: "" },
    HeaderSig { name: "BunnyCDN", category: "CDN", header: "cdn-pullzone", pattern: "", version_prefix: "" },
    HeaderSig { name: "BunnyCDN", category: "CDN", header: "cdn-uid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Edgecast", category: "CDN", header: "server", pattern: "ecs", version_prefix: "" },
    HeaderSig { name: "Limelight", category: "CDN", header: "server", pattern: "llnw", version_prefix: "" },
    HeaderSig { name: "ChinaNetCenter", category: "CDN", header: "server", pattern: "cnc", version_prefix: "" },
    HeaderSig { name: "CDNetworks", category: "CDN", header: "server", pattern: "cdnetworks", version_prefix: "" },
    HeaderSig { name: "ArvanCloud", category: "CDN", header: "server", pattern: "arvancloud", version_prefix: "" },
    HeaderSig { name: "G-Core CDN", category: "CDN", header: "server", pattern: "g-core", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Netlify", category: "PaaS", header: "x-nf-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Netlify", category: "PaaS", header: "server", pattern: "netlify", version_prefix: "" },
    HeaderSig { name: "Netlify", category: "PaaS", header: "x-netlify-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Vercel", category: "PaaS", header: "x-vercel-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Vercel", category: "PaaS", header: "x-vercel-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Vercel", category: "PaaS", header: "server", pattern: "vercel", version_prefix: "" },
    HeaderSig { name: "Render", category: "PaaS", header: "server", pattern: "render", version_prefix: "" },
    HeaderSig { name: "Render", category: "PaaS", header: "x-render-origin-server", pattern: "", version_prefix: "" },
    HeaderSig { name: "Railway", category: "PaaS", header: "server", pattern: "railway", version_prefix: "" },
    HeaderSig { name: "Fly.io", category: "PaaS", header: "fly-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Fly.io", category: "PaaS", header: "server", pattern: "fly", version_prefix: "" },
    HeaderSig { name: "Heroku", category: "PaaS", header: "via", pattern: "heroku", version_prefix: "" },

    // -- CDN --
    HeaderSig { name: "AWS CloudFront", category: "CDN", header: "x-amz-cf-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "AWS CloudFront", category: "CDN", header: "server", pattern: "cloudfront", version_prefix: "" },

    // -- Load Balancer --
    HeaderSig { name: "AWS ELB", category: "Load Balancer", header: "server", pattern: "awselb", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "AWS S3", category: "Storage", header: "server", pattern: "amazons3", version_prefix: "" },

    // -- CDN --
    HeaderSig { name: "Google Cloud CDN", category: "CDN", header: "x-goog-cdn-project-id", pattern: "", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Firebase", category: "PaaS", header: "x-firebase-deployment", pattern: "", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "Azure Blob", category: "Storage", header: "server", pattern: "windows-azure-blob", version_prefix: "" },

    // -- CDN --
    HeaderSig { name: "Azure CDN", category: "CDN", header: "x-msedge-ref", pattern: "", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Surge", category: "PaaS", header: "server", pattern: "surge", version_prefix: "" },
    HeaderSig { name: "GitHub Pages", category: "PaaS", header: "server", pattern: "github.com", version_prefix: "" },
    HeaderSig { name: "GitLab Pages", category: "PaaS", header: "server", pattern: "gitlab-pages", version_prefix: "" },

    // -- CDN/WAF --
    HeaderSig { name: "Stormwall", category: "CDN/WAF", header: "server", pattern: "stormwall", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Shopify", category: "eCommerce", header: "x-shopify-stage", pattern: "", version_prefix: "" },
    HeaderSig { name: "Shopify", category: "eCommerce", header: "x-shopid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Shopify", category: "eCommerce", header: "set-cookie", pattern: "_shopify_", version_prefix: "" },
    HeaderSig { name: "BigCommerce", category: "eCommerce", header: "x-bc-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "BigCommerce", category: "eCommerce", header: "x-powered-by", pattern: "bigcommerce", version_prefix: "" },
    HeaderSig { name: "Volusion", category: "eCommerce", header: "x-powered-by", pattern: "volusion", version_prefix: "" },
    HeaderSig { name: "Ecwid", category: "eCommerce", header: "x-powered-by", pattern: "ecwid", version_prefix: "" },
    HeaderSig { name: "Salesforce Commerce", category: "eCommerce", header: "x-powered-by", pattern: "salesforce commerce", version_prefix: "" },
    HeaderSig { name: "SAP Commerce", category: "eCommerce", header: "x-powered-by", pattern: "sap commerce", version_prefix: "" },
    HeaderSig { name: "Saleor", category: "eCommerce", header: "x-powered-by", pattern: "saleor", version_prefix: "" },
    HeaderSig { name: "Vendure", category: "eCommerce", header: "x-powered-by", pattern: "vendure", version_prefix: "" },
    HeaderSig { name: "Spree", category: "eCommerce", header: "x-powered-by", pattern: "spree", version_prefix: "" },
    HeaderSig { name: "Solidus", category: "eCommerce", header: "x-powered-by", pattern: "solidus", version_prefix: "" },
    HeaderSig { name: "Sylius", category: "eCommerce", header: "x-powered-by", pattern: "sylius", version_prefix: "" },
    HeaderSig { name: "Bagisto", category: "eCommerce", header: "x-powered-by", pattern: "bagisto", version_prefix: "" },
    HeaderSig { name: "osCommerce", category: "eCommerce", header: "set-cookie", pattern: "oscsid", version_prefix: "" },
    HeaderSig { name: "ZenCart", category: "eCommerce", header: "set-cookie", pattern: "zenid", version_prefix: "" },
    HeaderSig { name: "3dcart", category: "eCommerce", header: "x-powered-by", pattern: "3dcart", version_prefix: "" },
    HeaderSig { name: "Shopware", category: "eCommerce", header: "x-powered-by", pattern: "shopware", version_prefix: "" },
    HeaderSig { name: "Shopware", category: "eCommerce", header: "set-cookie", pattern: "shopware", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Squarespace", category: "CMS", header: "server", pattern: "squarespace", version_prefix: "" },
    HeaderSig { name: "Squarespace", category: "CMS", header: "x-powered-by", pattern: "squarespace", version_prefix: "" },
    HeaderSig { name: "Wix", category: "CMS", header: "server", pattern: "wix", version_prefix: "" },
    HeaderSig { name: "Wix", category: "CMS", header: "x-wix-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Webflow", category: "CMS", header: "server", pattern: "webflow", version_prefix: "" },
    HeaderSig { name: "Webflow", category: "CMS", header: "x-webflow-info", pattern: "", version_prefix: "" },

    // -- Email Server --
    HeaderSig { name: "Postfix", category: "Email Server", header: "server", pattern: "postfix", version_prefix: "" },
    HeaderSig { name: "Sendmail", category: "Email Server", header: "server", pattern: "sendmail", version_prefix: "" },
    HeaderSig { name: "Exim", category: "Email Server", header: "server", pattern: "exim", version_prefix: "exim" },
    HeaderSig { name: "qmail", category: "Email Server", header: "server", pattern: "qmail", version_prefix: "" },
    HeaderSig { name: "hMailServer", category: "Email Server", header: "server", pattern: "hmailserver", version_prefix: "" },
    HeaderSig { name: "Zimbra", category: "Email Server", header: "server", pattern: "zimbra", version_prefix: "" },
    HeaderSig { name: "Zimbra", category: "Email Server", header: "set-cookie", pattern: "zm_auth_token", version_prefix: "" },
    HeaderSig { name: "Dovecot", category: "Email Server", header: "server", pattern: "dovecot", version_prefix: "" },
    HeaderSig { name: "Courier", category: "Email Server", header: "server", pattern: "courier", version_prefix: "" },
    HeaderSig { name: "Microsoft Exchange", category: "Email Server", header: "x-owa-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Microsoft Exchange", category: "Email Server", header: "x-feserver", pattern: "", version_prefix: "" },
    HeaderSig { name: "Microsoft Exchange", category: "Email Server", header: "x-beserver", pattern: "", version_prefix: "" },
    HeaderSig { name: "GroupWise", category: "Email Server", header: "server", pattern: "groupwise", version_prefix: "" },
    HeaderSig { name: "SOGo", category: "Email Server", header: "server", pattern: "sogo", version_prefix: "" },

    // -- Webmail --
    HeaderSig { name: "Rainloop", category: "Webmail", header: "x-powered-by", pattern: "rainloop", version_prefix: "" },
    HeaderSig { name: "Afterlogic", category: "Webmail", header: "x-powered-by", pattern: "afterlogic", version_prefix: "" },

    // -- Email --
    HeaderSig { name: "Mailtrain", category: "Email", header: "x-powered-by", pattern: "mailtrain", version_prefix: "" },

    // -- Media Server --
    HeaderSig { name: "Plex", category: "Media Server", header: "x-plex-protocol", pattern: "", version_prefix: "" },
    HeaderSig { name: "Plex", category: "Media Server", header: "server", pattern: "plex", version_prefix: "" },
    HeaderSig { name: "Jellyfin", category: "Media Server", header: "server", pattern: "jellyfin", version_prefix: "" },
    HeaderSig { name: "Emby", category: "Media Server", header: "server", pattern: "emby", version_prefix: "" },
    HeaderSig { name: "Kodi", category: "Media Server", header: "server", pattern: "kodi", version_prefix: "" },
    HeaderSig { name: "MiniDLNA", category: "Media Server", header: "server", pattern: "minidlna", version_prefix: "minidlna" },
    HeaderSig { name: "Subsonic", category: "Media Server", header: "server", pattern: "subsonic", version_prefix: "" },
    HeaderSig { name: "Airsonic", category: "Media Server", header: "server", pattern: "airsonic", version_prefix: "" },
    HeaderSig { name: "Navidrome", category: "Media Server", header: "server", pattern: "navidrome", version_prefix: "" },

    // -- Streaming Server --
    HeaderSig { name: "Liquidsoap", category: "Streaming Server", header: "server", pattern: "liquidsoap", version_prefix: "" },
    HeaderSig { name: "nginx-rtmp", category: "Streaming Server", header: "server", pattern: "nginx-rtmp", version_prefix: "" },
    HeaderSig { name: "Wowza", category: "Streaming Server", header: "server", pattern: "wowza", version_prefix: "" },
    HeaderSig { name: "Ant Media", category: "Streaming Server", header: "server", pattern: "ant media", version_prefix: "" },
    HeaderSig { name: "Red5", category: "Streaming Server", header: "server", pattern: "red5", version_prefix: "" },

    // -- IoT --
    HeaderSig { name: "Tasmota", category: "IoT", header: "server", pattern: "tasmota", version_prefix: "" },
    HeaderSig { name: "ESPHome", category: "IoT", header: "server", pattern: "esphome", version_prefix: "" },
    HeaderSig { name: "Home Assistant", category: "IoT", header: "server", pattern: "homeassistant", version_prefix: "" },
    HeaderSig { name: "Home Assistant", category: "IoT", header: "x-ha-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Node-RED", category: "IoT", header: "server", pattern: "node-red", version_prefix: "" },

    // -- MQTT --
    HeaderSig { name: "Mosquitto", category: "MQTT", header: "server", pattern: "mosquitto", version_prefix: "" },
    HeaderSig { name: "HiveMQ", category: "MQTT", header: "server", pattern: "hivemq", version_prefix: "" },
    HeaderSig { name: "EMQX", category: "MQTT", header: "server", pattern: "emqx", version_prefix: "" },
    HeaderSig { name: "VerneMQ", category: "MQTT", header: "server", pattern: "vernemq", version_prefix: "" },

    // -- IoT --
    HeaderSig { name: "MicroPython", category: "IoT", header: "server", pattern: "micropython", version_prefix: "" },
    HeaderSig { name: "CircuitPython", category: "IoT", header: "server", pattern: "circuitpython", version_prefix: "" },
    HeaderSig { name: "Zigbee2MQTT", category: "IoT", header: "server", pattern: "zigbee2mqtt", version_prefix: "" },
    HeaderSig { name: "Domoticz", category: "IoT", header: "server", pattern: "domoticz", version_prefix: "" },
    HeaderSig { name: "OpenHAB", category: "IoT", header: "server", pattern: "openhab", version_prefix: "" },
    HeaderSig { name: "ioBroker", category: "IoT", header: "server", pattern: "iobroker", version_prefix: "" },
    HeaderSig { name: "Contiki", category: "IoT", header: "server", pattern: "contiki", version_prefix: "" },
    HeaderSig { name: "RIOT OS", category: "IoT", header: "server", pattern: "riot", version_prefix: "" },
    HeaderSig { name: "Arduino", category: "IoT", header: "server", pattern: "arduino", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Contentful", category: "Headless CMS", header: "x-contentful-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Contentful", category: "Headless CMS", header: "x-contentful-route", pattern: "", version_prefix: "" },
    HeaderSig { name: "Sanity", category: "Headless CMS", header: "x-sanity-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Storyblok", category: "Headless CMS", header: "x-storyblok-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Prismic", category: "Headless CMS", header: "x-prismic-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "DatoCMS", category: "Headless CMS", header: "x-dato-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Butter CMS", category: "Headless CMS", header: "x-powered-by", pattern: "buttercms", version_prefix: "" },
    HeaderSig { name: "Cockpit CMS", category: "Headless CMS", header: "x-powered-by", pattern: "cockpit", version_prefix: "" },
    HeaderSig { name: "Tina CMS", category: "Headless CMS", header: "x-powered-by", pattern: "tinacms", version_prefix: "" },
    HeaderSig { name: "Contentstack", category: "Headless CMS", header: "x-contentstack-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Agility CMS", category: "Headless CMS", header: "x-agility-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Netlify CMS", category: "Headless CMS", header: "x-powered-by", pattern: "netlify-cms", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Blogger", category: "CMS", header: "server", pattern: "blogger", version_prefix: "" },
    HeaderSig { name: "Tumblr", category: "CMS", header: "server", pattern: "tumblr", version_prefix: "" },
    HeaderSig { name: "Tumblr", category: "CMS", header: "x-tumblr-user", pattern: "", version_prefix: "" },
    HeaderSig { name: "Medium", category: "CMS", header: "x-powered-by", pattern: "medium", version_prefix: "" },
    HeaderSig { name: "Adobe Experience Manager", category: "CMS", header: "server", pattern: "day-servlet-engine", version_prefix: "" },
    HeaderSig { name: "Adobe Experience Manager", category: "CMS", header: "dispatcher", pattern: "", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Acquia", category: "PaaS", header: "x-ah-environment", pattern: "", version_prefix: "" },
    HeaderSig { name: "Acquia", category: "PaaS", header: "x-ah-site", pattern: "", version_prefix: "" },
    HeaderSig { name: "Pantheon", category: "PaaS", header: "x-pantheon-styx-hostname", pattern: "", version_prefix: "" },
    HeaderSig { name: "Pantheon", category: "PaaS", header: "x-styx-req-id", pattern: "", version_prefix: "" },

    // -- Hosting --
    HeaderSig { name: "WP Engine", category: "Hosting", header: "x-powered-by", pattern: "wp engine", version_prefix: "" },
    HeaderSig { name: "WP Engine", category: "Hosting", header: "wpe-backend", pattern: "", version_prefix: "" },
    HeaderSig { name: "Kinsta", category: "Hosting", header: "x-kinsta-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Flywheel", category: "Hosting", header: "x-powered-by", pattern: "flywheel", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Hubspot CMS", category: "CMS", header: "x-hs-content-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hubspot CMS", category: "CMS", header: "x-hs-hub-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hubspot CMS", category: "CMS", header: "x-powered-by", pattern: "hubspot", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Kentico Kontent", category: "Headless CMS", header: "x-kontent-request-id", pattern: "", version_prefix: "" },

    // -- Cache --
    HeaderSig { name: "Varnish", category: "Cache", header: "x-varnish-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Nginx Cache", category: "Cache", header: "x-nginx-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "LiteSpeed Cache", category: "Cache", header: "x-litespeed-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "W3 Total Cache", category: "Cache", header: "x-powered-by", pattern: "w3 total cache", version_prefix: "" },
    HeaderSig { name: "WP Super Cache", category: "Cache", header: "x-powered-by", pattern: "wp super cache", version_prefix: "" },
    HeaderSig { name: "WP Rocket", category: "Cache", header: "x-powered-by", pattern: "wp rocket", version_prefix: "" },
    HeaderSig { name: "WP Fastest Cache", category: "Cache", header: "x-powered-by", pattern: "wp fastest cache", version_prefix: "" },
    HeaderSig { name: "Redis Object Cache", category: "Cache", header: "x-redis-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "Memcached", category: "Cache", header: "x-memcached", pattern: "", version_prefix: "" },

    // -- Optimization --
    HeaderSig { name: "PageSpeed", category: "Optimization", header: "x-mod-pagespeed", pattern: "", version_prefix: "" },
    HeaderSig { name: "PageSpeed", category: "Optimization", header: "x-page-speed", pattern: "", version_prefix: "" },

    // -- Cache --
    HeaderSig { name: "Batcache", category: "Cache", header: "x-batcache", pattern: "", version_prefix: "" },
    HeaderSig { name: "SG Optimizer", category: "Cache", header: "x-powered-by", pattern: "sg optimizer", version_prefix: "" },

    // -- API --
    HeaderSig { name: "GraphQL", category: "API", header: "x-graphql-event-stream", pattern: "", version_prefix: "" },
    HeaderSig { name: "GraphQL Yoga", category: "API", header: "x-graphql-yoga", pattern: "", version_prefix: "" },
    HeaderSig { name: "Apollo Server", category: "API", header: "x-apollo-operation-name", pattern: "", version_prefix: "" },
    HeaderSig { name: "PostgREST", category: "API", header: "server", pattern: "postgrest", version_prefix: "postgrest" },

    // -- BaaS --
    HeaderSig { name: "Appwrite", category: "BaaS", header: "x-powered-by", pattern: "appwrite", version_prefix: "" },
    HeaderSig { name: "Appwrite", category: "BaaS", header: "x-appwrite-node", pattern: "", version_prefix: "" },
    HeaderSig { name: "Parse Server", category: "BaaS", header: "x-parse-platform", pattern: "", version_prefix: "" },
    HeaderSig { name: "PocketBase", category: "BaaS", header: "server", pattern: "pocketbase", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Frappe", category: "Web Framework", header: "x-powered-by", pattern: "frappe", version_prefix: "" },

    // -- ERP --
    HeaderSig { name: "ERPNext", category: "ERP", header: "x-powered-by", pattern: "erpnext", version_prefix: "" },
    HeaderSig { name: "Odoo", category: "ERP", header: "server", pattern: "odoo", version_prefix: "" },
    HeaderSig { name: "SAP", category: "ERP", header: "server", pattern: "sap", version_prefix: "" },
    HeaderSig { name: "SAP", category: "ERP", header: "sap-server", pattern: "", version_prefix: "" },

    // -- Wiki --
    HeaderSig { name: "Confluence", category: "Wiki", header: "x-confluence-request-time", pattern: "", version_prefix: "" },
    HeaderSig { name: "Confluence", category: "Wiki", header: "set-cookie", pattern: "confluence", version_prefix: "" },

    // -- Project Management --
    HeaderSig { name: "Jira", category: "Project Management", header: "x-jira-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Jira", category: "Project Management", header: "set-cookie", pattern: "atlassian.xsrf.token", version_prefix: "" },
    HeaderSig { name: "Redmine", category: "Project Management", header: "x-powered-by", pattern: "redmine", version_prefix: "" },
    HeaderSig { name: "YouTrack", category: "Project Management", header: "server", pattern: "youtrack", version_prefix: "" },
    HeaderSig { name: "Trac", category: "Project Management", header: "x-powered-by", pattern: "trac", version_prefix: "" },

    // -- Messaging --
    HeaderSig { name: "Mattermost", category: "Messaging", header: "x-powered-by", pattern: "mattermost", version_prefix: "" },
    HeaderSig { name: "Mattermost", category: "Messaging", header: "x-version-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Rocket.Chat", category: "Messaging", header: "x-powered-by", pattern: "rocket.chat", version_prefix: "" },

    // -- Forum --
    HeaderSig { name: "Discourse", category: "Forum", header: "x-discourse-route", pattern: "", version_prefix: "" },
    HeaderSig { name: "Flarum", category: "Forum", header: "x-powered-by", pattern: "flarum", version_prefix: "" },
    HeaderSig { name: "phpBB", category: "Forum", header: "set-cookie", pattern: "phpbb_", version_prefix: "" },
    HeaderSig { name: "vBulletin", category: "Forum", header: "set-cookie", pattern: "bbsessionhash", version_prefix: "" },
    HeaderSig { name: "MyBB", category: "Forum", header: "set-cookie", pattern: "mybbuser", version_prefix: "" },
    HeaderSig { name: "XenForo", category: "Forum", header: "set-cookie", pattern: "xf_csrf", version_prefix: "" },
    HeaderSig { name: "XenForo", category: "Forum", header: "x-powered-by", pattern: "xenforo", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "MinIO", category: "Storage", header: "server", pattern: "minio", version_prefix: "" },
    HeaderSig { name: "MinIO", category: "Storage", header: "x-minio-deployment-id", pattern: "", version_prefix: "" },

    // -- Container Management --
    HeaderSig { name: "Portainer", category: "Container Management", header: "x-portainer-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Rancher", category: "Container Management", header: "x-powered-by", pattern: "rancher", version_prefix: "" },

    // -- Load Balancer --
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "server", pattern: "haproxy", version_prefix: "" },
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "via", pattern: "haproxy", version_prefix: "" },

    // -- Serverless --
    HeaderSig { name: "Cloudflare Workers", category: "Serverless", header: "cf-worker", pattern: "", version_prefix: "" },
    HeaderSig { name: "AWS Lambda", category: "Serverless", header: "x-amz-function-error", pattern: "", version_prefix: "" },
    HeaderSig { name: "Azure Functions", category: "Serverless", header: "x-azure-functions-invocationid", pattern: "", version_prefix: "" },
    HeaderSig { name: "OpenFaaS", category: "Serverless", header: "x-start-time", pattern: "", version_prefix: "" },

    // -- Analytics --
    HeaderSig { name: "Plausible", category: "Analytics", header: "x-plausible-url", pattern: "", version_prefix: "" },
    HeaderSig { name: "Matomo", category: "Analytics", header: "set-cookie", pattern: "_pk_id", version_prefix: "" },
    HeaderSig { name: "Matomo", category: "Analytics", header: "x-matomo-request-id", pattern: "", version_prefix: "" },

    // -- Message Queue --
    HeaderSig { name: "RabbitMQ", category: "Message Queue", header: "server", pattern: "rabbitmq", version_prefix: "" },
    HeaderSig { name: "Apache Kafka", category: "Message Queue", header: "server", pattern: "kafka", version_prefix: "" },
    HeaderSig { name: "Apache ActiveMQ", category: "Message Queue", header: "server", pattern: "activemq", version_prefix: "" },

    // -- Coordination --
    HeaderSig { name: "etcd", category: "Coordination", header: "server", pattern: "etcd", version_prefix: "" },

    // -- Service Discovery --
    HeaderSig { name: "Consul", category: "Service Discovery", header: "server", pattern: "consul", version_prefix: "" },

    // -- Secrets Management --
    HeaderSig { name: "Vault", category: "Secrets Management", header: "server", pattern: "vault", version_prefix: "" },
    HeaderSig { name: "Vault", category: "Secrets Management", header: "x-vault-token", pattern: "", version_prefix: "" },

    // -- Orchestration --
    HeaderSig { name: "Nomad", category: "Orchestration", header: "server", pattern: "nomad", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "Ceph", category: "Storage", header: "server", pattern: "ceph", version_prefix: "" },

    // -- Notebook --
    HeaderSig { name: "Jupyter", category: "Notebook", header: "server", pattern: "jupyter", version_prefix: "" },
    HeaderSig { name: "JupyterHub", category: "Notebook", header: "server", pattern: "jupyterhub", version_prefix: "" },

    // -- IDE --
    HeaderSig { name: "RStudio", category: "IDE", header: "server", pattern: "rstudio", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Streamlit", category: "Web Framework", header: "server", pattern: "streamlit", version_prefix: "" },
    HeaderSig { name: "Gradio", category: "Web Framework", header: "server", pattern: "gradio", version_prefix: "" },
    HeaderSig { name: "Dash", category: "Web Framework", header: "x-powered-by", pattern: "dash", version_prefix: "" },

    // -- ML Platform --
    HeaderSig { name: "MLflow", category: "ML Platform", header: "server", pattern: "mlflow", version_prefix: "" },
    HeaderSig { name: "Kubeflow", category: "ML Platform", header: "server", pattern: "kubeflow", version_prefix: "" },

    // -- Orchestration --
    HeaderSig { name: "Airflow", category: "Orchestration", header: "server", pattern: "airflow", version_prefix: "" },

    // -- Analytics --
    HeaderSig { name: "Apache Superset", category: "Analytics", header: "server", pattern: "superset", version_prefix: "" },
    HeaderSig { name: "Metabase", category: "Analytics", header: "x-metabase-session", pattern: "", version_prefix: "" },
    HeaderSig { name: "Metabase", category: "Analytics", header: "server", pattern: "metabase", version_prefix: "" },
    HeaderSig { name: "Redash", category: "Analytics", header: "x-powered-by", pattern: "redash", version_prefix: "" },

    // -- DNS --
    HeaderSig { name: "Pi-hole", category: "DNS", header: "x-pi-hole", pattern: "", version_prefix: "" },
    HeaderSig { name: "AdGuard Home", category: "DNS", header: "server", pattern: "adguard", version_prefix: "" },
    HeaderSig { name: "CoreDNS", category: "DNS", header: "server", pattern: "coredns", version_prefix: "" },
    HeaderSig { name: "PowerDNS", category: "DNS", header: "server", pattern: "powerdns", version_prefix: "" },

    // -- Reverse Proxy --
    HeaderSig { name: "Traefik", category: "Reverse Proxy", header: "x-traefik-middleware", pattern: "", version_prefix: "" },

    // -- Tunnel --
    HeaderSig { name: "ngrok", category: "Tunnel", header: "server", pattern: "ngrok", version_prefix: "" },

    // -- WordPress Plugin --
    HeaderSig { name: "Elementor", category: "WordPress Plugin", header: "x-elementor", pattern: "", version_prefix: "" },
    HeaderSig { name: "Yoast SEO", category: "WordPress Plugin", header: "x-yoast-seo", pattern: "", version_prefix: "" },
    HeaderSig { name: "WPBakery", category: "WordPress Plugin", header: "x-powered-by", pattern: "wpbakery", version_prefix: "" },
    HeaderSig { name: "Beaver Builder", category: "WordPress Plugin", header: "x-powered-by", pattern: "beaver builder", version_prefix: "" },
    HeaderSig { name: "Divi", category: "WordPress Plugin", header: "x-powered-by", pattern: "divi", version_prefix: "" },
    HeaderSig { name: "BuddyPress", category: "WordPress Plugin", header: "x-powered-by", pattern: "buddypress", version_prefix: "" },
    HeaderSig { name: "Jetpack", category: "WordPress Plugin", header: "x-jetpack-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "WPML", category: "WordPress Plugin", header: "set-cookie", pattern: "wpml_", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "WebtoB", category: "Web Server", header: "server", pattern: "webtob", version_prefix: "webtob" },

    // -- Application Server --
    HeaderSig { name: "JEUS", category: "Application Server", header: "server", pattern: "jeus", version_prefix: "jeus" },
    HeaderSig { name: "Tmax", category: "Application Server", header: "server", pattern: "tmax", version_prefix: "" },
    HeaderSig { name: "OFBiz", category: "Application Server", header: "server", pattern: "ofbiz", version_prefix: "" },
    HeaderSig { name: "Apache Geronimo", category: "Application Server", header: "server", pattern: "geronimo", version_prefix: "" },
    HeaderSig { name: "TongWeb", category: "Application Server", header: "server", pattern: "tongweb", version_prefix: "" },
    HeaderSig { name: "Apusic", category: "Application Server", header: "server", pattern: "apusic", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "GBase", category: "Database", header: "server", pattern: "gbase", version_prefix: "" },
    HeaderSig { name: "OceanBase", category: "Database", header: "server", pattern: "oceanbase", version_prefix: "" },
    HeaderSig { name: "PolarDB", category: "Database", header: "server", pattern: "polardb", version_prefix: "" },
    HeaderSig { name: "Doris", category: "Database", header: "server", pattern: "doris", version_prefix: "" },
    HeaderSig { name: "StarRocks", category: "Database", header: "server", pattern: "starrocks", version_prefix: "" },
    HeaderSig { name: "Apache Druid", category: "Database", header: "server", pattern: "druid", version_prefix: "" },

    // -- Data Processing --
    HeaderSig { name: "Apache Flink", category: "Data Processing", header: "server", pattern: "flink", version_prefix: "" },
    HeaderSig { name: "Apache Spark", category: "Data Processing", header: "server", pattern: "spark", version_prefix: "" },
    HeaderSig { name: "Apache NiFi", category: "Data Processing", header: "server", pattern: "nifi", version_prefix: "" },

    // -- ECM --
    HeaderSig { name: "Alfresco", category: "ECM", header: "server", pattern: "alfresco", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "OpenCMS", category: "CMS", header: "x-powered-by", pattern: "opencms", version_prefix: "" },
    HeaderSig { name: "Magnolia CMS", category: "CMS", header: "x-powered-by", pattern: "magnolia", version_prefix: "" },
    HeaderSig { name: "Jahia", category: "CMS", header: "x-powered-by", pattern: "jahia", version_prefix: "" },
    HeaderSig { name: "eZ Platform", category: "CMS", header: "x-powered-by", pattern: "ez platform", version_prefix: "" },
    HeaderSig { name: "Neos CMS", category: "CMS", header: "x-powered-by", pattern: "neos", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Neos Flow", category: "Web Framework", header: "x-flow-powered", pattern: "", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "MODX", category: "CMS", header: "x-powered-by", pattern: "modx", version_prefix: "" },
    HeaderSig { name: "MODX", category: "CMS", header: "set-cookie", pattern: "modx_", version_prefix: "" },
    HeaderSig { name: "Backdrop", category: "CMS", header: "x-generator", pattern: "backdrop", version_prefix: "" },
    HeaderSig { name: "Fork CMS", category: "CMS", header: "x-powered-by", pattern: "fork cms", version_prefix: "" },
    HeaderSig { name: "ImpressCMS", category: "CMS", header: "x-powered-by", pattern: "impresscms", version_prefix: "" },
    HeaderSig { name: "Xoops", category: "CMS", header: "x-powered-by", pattern: "xoops", version_prefix: "" },
    HeaderSig { name: "CMS Made Simple", category: "CMS", header: "x-powered-by", pattern: "cms made simple", version_prefix: "" },
    HeaderSig { name: "Tiki Wiki", category: "CMS", header: "set-cookie", pattern: "tiki_", version_prefix: "" },

    // -- Wiki --
    HeaderSig { name: "DokuWiki", category: "Wiki", header: "x-powered-by", pattern: "dokuwiki", version_prefix: "" },
    HeaderSig { name: "DokuWiki", category: "Wiki", header: "set-cookie", pattern: "dokuwiki", version_prefix: "" },
    HeaderSig { name: "MediaWiki", category: "Wiki", header: "x-powered-by", pattern: "mediawiki", version_prefix: "" },
    HeaderSig { name: "MediaWiki", category: "Wiki", header: "x-generator", pattern: "mediawiki", version_prefix: "" },
    HeaderSig { name: "PmWiki", category: "Wiki", header: "x-powered-by", pattern: "pmwiki", version_prefix: "" },
    HeaderSig { name: "Foswiki", category: "Wiki", header: "x-powered-by", pattern: "foswiki", version_prefix: "" },
    HeaderSig { name: "XWiki", category: "Wiki", header: "x-powered-by", pattern: "xwiki", version_prefix: "" },
    HeaderSig { name: "BookStack", category: "Wiki", header: "x-powered-by", pattern: "bookstack", version_prefix: "" },
    HeaderSig { name: "Outline", category: "Wiki", header: "x-powered-by", pattern: "outline", version_prefix: "" },
    HeaderSig { name: "Wiki.js", category: "Wiki", header: "x-powered-by", pattern: "wiki.js", version_prefix: "" },

    // -- Documentation --
    HeaderSig { name: "Gitbook", category: "Documentation", header: "x-powered-by", pattern: "gitbook", version_prefix: "" },
    HeaderSig { name: "ReadTheDocs", category: "Documentation", header: "x-rtd-project", pattern: "", version_prefix: "" },
    HeaderSig { name: "ReadTheDocs", category: "Documentation", header: "x-rtd-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Docusaurus", category: "Documentation", header: "x-powered-by", pattern: "docusaurus", version_prefix: "" },
    HeaderSig { name: "MkDocs", category: "Documentation", header: "x-powered-by", pattern: "mkdocs", version_prefix: "" },
    HeaderSig { name: "VuePress", category: "Documentation", header: "x-powered-by", pattern: "vuepress", version_prefix: "" },

    // -- NAS --
    HeaderSig { name: "Synology", category: "NAS", header: "server", pattern: "synology", version_prefix: "" },
    HeaderSig { name: "Synology", category: "NAS", header: "set-cookie", pattern: "smid", version_prefix: "" },
    HeaderSig { name: "QNAP", category: "NAS", header: "server", pattern: "qnap", version_prefix: "" },
    HeaderSig { name: "TrueNAS", category: "NAS", header: "server", pattern: "truenas", version_prefix: "" },
    HeaderSig { name: "FreeNAS", category: "NAS", header: "server", pattern: "freenas", version_prefix: "" },

    // -- Virtualization --
    HeaderSig { name: "Proxmox", category: "Virtualization", header: "server", pattern: "pve-api-daemon", version_prefix: "" },
    HeaderSig { name: "Proxmox", category: "Virtualization", header: "set-cookie", pattern: "pveauthcookie", version_prefix: "" },
    HeaderSig { name: "VMware", category: "Virtualization", header: "server", pattern: "vmware", version_prefix: "" },
    HeaderSig { name: "VMware vCenter", category: "Virtualization", header: "server", pattern: "vcenter", version_prefix: "" },

    // -- Project Management --
    HeaderSig { name: "Taiga", category: "Project Management", header: "server", pattern: "taiga", version_prefix: "" },
    HeaderSig { name: "OpenProject", category: "Project Management", header: "server", pattern: "openproject", version_prefix: "" },

    // -- Productivity --
    HeaderSig { name: "Notion", category: "Productivity", header: "x-notion-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Airtable", category: "Productivity", header: "x-airtable-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Basecamp", category: "Productivity", header: "x-powered-by", pattern: "basecamp", version_prefix: "" },

    // -- Communication --
    HeaderSig { name: "Twilio", category: "Communication", header: "x-twilio-request-id", pattern: "", version_prefix: "" },

    // -- Email Service --
    HeaderSig { name: "SendGrid", category: "Email Service", header: "x-message-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Mailgun", category: "Email Service", header: "x-mailgun-sid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Postmark", category: "Email Service", header: "x-pm-message-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Mailchimp", category: "Email Service", header: "x-mailchimp-request-id", pattern: "", version_prefix: "" },

    // -- Media --
    HeaderSig { name: "Cloudinary", category: "Media", header: "x-cld-error", pattern: "", version_prefix: "" },
    HeaderSig { name: "imgix", category: "Media", header: "x-imgix-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Uploadcare", category: "Media", header: "x-uploadcare-cdn", pattern: "", version_prefix: "" },
    HeaderSig { name: "Thumbor", category: "Media", header: "server", pattern: "thumbor", version_prefix: "" },

    // -- Programming Language --
    HeaderSig { name: "PHP", category: "Programming Language", header: "x-powered-by", pattern: "php", version_prefix: "php" },
    HeaderSig { name: "PHP", category: "Programming Language", header: "set-cookie", pattern: "phpsessid", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "ASP.NET Session", category: "Web Framework", header: "set-cookie", pattern: "asp.net_sessionid", version_prefix: "" },
    HeaderSig { name: "JSP", category: "Web Framework", header: "set-cookie", pattern: "jsessionid", version_prefix: "" },
    HeaderSig { name: "ColdFusion", category: "Web Framework", header: "set-cookie", pattern: "cfid", version_prefix: "" },
    HeaderSig { name: "ColdFusion", category: "Web Framework", header: "set-cookie", pattern: "cftoken", version_prefix: "" },
    HeaderSig { name: "ColdFusion", category: "Web Framework", header: "x-powered-by", pattern: "coldfusion", version_prefix: "" },

    // -- Programming Language --
    HeaderSig { name: "Perl", category: "Programming Language", header: "x-powered-by", pattern: "perl", version_prefix: "" },

    // -- Runtime --
    HeaderSig { name: "Node.js", category: "Runtime", header: "x-powered-by", pattern: "nodejs", version_prefix: "" },
    HeaderSig { name: "Node.js", category: "Runtime", header: "x-powered-by", pattern: "node.js", version_prefix: "" },
    // =========================================================================
    // EXPANDED SIGNATURES DATABASE PART 2 (303 additional entries)
    // =========================================================================

    // -- Web Server --
    HeaderSig { name: "H2O", category: "Web Server", header: "server", pattern: "h2o", version_prefix: "h2o" },
    HeaderSig { name: "Tengine", category: "Web Server", header: "server", pattern: "tengine", version_prefix: "tengine" },
    HeaderSig { name: "OpenBSD httpd", category: "Web Server", header: "server", pattern: "openbsd httpd", version_prefix: "" },
    HeaderSig { name: "NetBSD bozohttpd", category: "Web Server", header: "server", pattern: "bozohttpd", version_prefix: "" },
    HeaderSig { name: "nginx-quic", category: "Web Server", header: "server", pattern: "nginx-quic", version_prefix: "" },
    HeaderSig { name: "Caddy", category: "Web Server", header: "server", pattern: "caddy", version_prefix: "" },
    HeaderSig { name: "LiteSpeed", category: "Web Server", header: "server", pattern: "litespeed", version_prefix: "litespeed" },
    HeaderSig { name: "nghttpx", category: "Web Server", header: "server", pattern: "nghttpx", version_prefix: "" },
    HeaderSig { name: "nghttpd", category: "Web Server", header: "server", pattern: "nghttpd", version_prefix: "" },
    HeaderSig { name: "Tengine", category: "Web Server", header: "via", pattern: "tengine", version_prefix: "" },
    HeaderSig { name: "cPanel", category: "Web Server", header: "server", pattern: "cpanel", version_prefix: "" },
    HeaderSig { name: "Plesk", category: "Web Server", header: "server", pattern: "sw-cp-server", version_prefix: "" },
    HeaderSig { name: "DirectAdmin", category: "Web Server", header: "server", pattern: "directadmin", version_prefix: "" },
    HeaderSig { name: "CentOS", category: "Web Server", header: "server", pattern: "centos", version_prefix: "" },
    HeaderSig { name: "OmniHTTPd", category: "Web Server", header: "server", pattern: "omnihttpd", version_prefix: "" },
    HeaderSig { name: "Pi-hole lighttpd", category: "Web Server", header: "server", pattern: "lighttpd", version_prefix: "lighttpd" },
    HeaderSig { name: "Communigate Pro", category: "Web Server", header: "server", pattern: "communigatepro", version_prefix: "" },
    HeaderSig { name: "Caudium", category: "Web Server", header: "server", pattern: "caudium", version_prefix: "caudium" },
    HeaderSig { name: "Tornado", category: "Web Server", header: "server", pattern: "tornado", version_prefix: "tornado" },
    HeaderSig { name: "grpc-gateway", category: "Web Server", header: "server", pattern: "grpc-gateway", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Fresh", category: "Web Framework", header: "x-powered-by", pattern: "fresh", version_prefix: "" },
    HeaderSig { name: "Oak", category: "Web Framework", header: "x-powered-by", pattern: "oak", version_prefix: "" },
    HeaderSig { name: "Aleph.js", category: "Web Framework", header: "x-powered-by", pattern: "aleph", version_prefix: "" },
    HeaderSig { name: "Midway", category: "Web Framework", header: "x-powered-by", pattern: "midway", version_prefix: "" },
    HeaderSig { name: "Egg.js", category: "Web Framework", header: "x-powered-by", pattern: "egg", version_prefix: "" },
    HeaderSig { name: "ThinkJS", category: "Web Framework", header: "x-powered-by", pattern: "thinkjs", version_prefix: "" },
    HeaderSig { name: "MidwayJS", category: "Web Framework", header: "x-powered-by", pattern: "midway.js", version_prefix: "" },
    HeaderSig { name: "Koa", category: "Web Framework", header: "server", pattern: "koa", version_prefix: "" },
    HeaderSig { name: "Hapi", category: "Web Framework", header: "server", pattern: "hapi", version_prefix: "" },
    HeaderSig { name: "Connect", category: "Web Framework", header: "x-powered-by", pattern: "connect", version_prefix: "" },
    HeaderSig { name: "Compressor", category: "Web Framework", header: "x-powered-by", pattern: "compressor", version_prefix: "" },
    HeaderSig { name: "Preact", category: "Web Framework", header: "x-powered-by", pattern: "preact", version_prefix: "" },
    HeaderSig { name: "Qwik", category: "Web Framework", header: "x-powered-by", pattern: "qwik", version_prefix: "" },
    HeaderSig { name: "Solid Start", category: "Web Framework", header: "x-powered-by", pattern: "solid-start", version_prefix: "" },
    HeaderSig { name: "Analog", category: "Web Framework", header: "x-powered-by", pattern: "analog", version_prefix: "" },
    HeaderSig { name: "Enhance", category: "Web Framework", header: "x-powered-by", pattern: "enhance", version_prefix: "" },
    HeaderSig { name: "ElectroDB", category: "Web Framework", header: "x-powered-by", pattern: "electrodb", version_prefix: "" },
    HeaderSig { name: "Responder", category: "Web Framework", header: "x-powered-by", pattern: "responder", version_prefix: "" },
    HeaderSig { name: "Vibora", category: "Web Framework", header: "server", pattern: "vibora", version_prefix: "" },
    HeaderSig { name: "Japronto", category: "Web Framework", header: "server", pattern: "japronto", version_prefix: "" },
    HeaderSig { name: "Emmett", category: "Web Framework", header: "server", pattern: "emmett", version_prefix: "" },
    HeaderSig { name: "Connexion", category: "Web Framework", header: "x-powered-by", pattern: "connexion", version_prefix: "" },
    HeaderSig { name: "Eve", category: "Web Framework", header: "x-powered-by", pattern: "eve", version_prefix: "" },
    HeaderSig { name: "Nameko", category: "Web Framework", header: "x-powered-by", pattern: "nameko", version_prefix: "" },
    HeaderSig { name: "Klein", category: "Web Framework", header: "server", pattern: "klein", version_prefix: "" },
    HeaderSig { name: "Morepath", category: "Web Framework", header: "x-powered-by", pattern: "morepath", version_prefix: "" },
    HeaderSig { name: "Bocadillo", category: "Web Framework", header: "server", pattern: "bocadillo", version_prefix: "" },
    HeaderSig { name: "Amp PHP", category: "Web Framework", header: "x-powered-by", pattern: "amphp", version_prefix: "" },

    // -- Web Server --
    HeaderSig { name: "Workerman", category: "Web Server", header: "server", pattern: "workerman", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "ThinkPHP", category: "Web Framework", header: "x-powered-by", pattern: "thinkphp", version_prefix: "" },
    HeaderSig { name: "ThinkPHP", category: "Web Framework", header: "set-cookie", pattern: "thinkphp_", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "PHPWind", category: "CMS", header: "x-powered-by", pattern: "phpwind", version_prefix: "" },

    // -- Forum --
    HeaderSig { name: "Discuz", category: "Forum", header: "set-cookie", pattern: "discuz_", version_prefix: "" },
    HeaderSig { name: "Discuz", category: "Forum", header: "x-powered-by", pattern: "discuz", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "DedeCMS", category: "CMS", header: "x-powered-by", pattern: "dedecms", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Ecshop", category: "eCommerce", header: "set-cookie", pattern: "ecsid", version_prefix: "" },
    HeaderSig { name: "Shopex", category: "eCommerce", header: "x-powered-by", pattern: "shopex", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Zblog", category: "CMS", header: "x-powered-by", pattern: "zblog", version_prefix: "" },
    HeaderSig { name: "Typecho", category: "CMS", header: "x-powered-by", pattern: "typecho", version_prefix: "" },
    HeaderSig { name: "Emlog", category: "CMS", header: "x-powered-by", pattern: "emlog", version_prefix: "" },
    HeaderSig { name: "PbootCMS", category: "CMS", header: "x-powered-by", pattern: "pbootcms", version_prefix: "" },

    // -- LMS --
    HeaderSig { name: "Moodle", category: "LMS", header: "x-powered-by", pattern: "moodle", version_prefix: "" },
    HeaderSig { name: "Moodle", category: "LMS", header: "set-cookie", pattern: "moodlesession", version_prefix: "" },
    HeaderSig { name: "Canvas LMS", category: "LMS", header: "x-canvas-meta", pattern: "", version_prefix: "" },
    HeaderSig { name: "Canvas LMS", category: "LMS", header: "set-cookie", pattern: "canvas_session", version_prefix: "" },
    HeaderSig { name: "Blackboard", category: "LMS", header: "x-blackboard", pattern: "", version_prefix: "" },
    HeaderSig { name: "Chamilo", category: "LMS", header: "x-powered-by", pattern: "chamilo", version_prefix: "" },
    HeaderSig { name: "Open edX", category: "LMS", header: "x-powered-by", pattern: "edx", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Ninja Framework", category: "Web Framework", header: "x-powered-by", pattern: "ninja", version_prefix: "" },
    HeaderSig { name: "Vert.x Web", category: "Web Framework", header: "x-powered-by", pattern: "vert.x-web", version_prefix: "" },
    HeaderSig { name: "Blade", category: "Web Framework", header: "server", pattern: "blade", version_prefix: "" },
    HeaderSig { name: "JFinal", category: "Web Framework", header: "x-powered-by", pattern: "jfinal", version_prefix: "" },
    HeaderSig { name: "Nutz", category: "Web Framework", header: "x-powered-by", pattern: "nutz", version_prefix: "" },
    HeaderSig { name: "Smart Framework", category: "Web Framework", header: "x-powered-by", pattern: "smart", version_prefix: "" },
    HeaderSig { name: "Jersey", category: "Web Framework", header: "x-powered-by", pattern: "jersey", version_prefix: "" },
    HeaderSig { name: "RestEasy", category: "Web Framework", header: "x-powered-by", pattern: "resteasy", version_prefix: "" },
    HeaderSig { name: "Apache Wicket", category: "Web Framework", header: "x-powered-by", pattern: "apache wicket", version_prefix: "" },
    HeaderSig { name: "ZK Framework", category: "Web Framework", header: "x-powered-by", pattern: "zk", version_prefix: "" },
    HeaderSig { name: "PrimeFaces", category: "Web Framework", header: "x-powered-by", pattern: "primefaces", version_prefix: "" },
    HeaderSig { name: "Apache Sling", category: "Web Framework", header: "server", pattern: "apache sling", version_prefix: "" },

    // -- Application Server --
    HeaderSig { name: "SAP NetWeaver", category: "Application Server", header: "server", pattern: "sap netweaver", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Gorilla", category: "Web Framework", header: "x-powered-by", pattern: "gorilla/mux", version_prefix: "" },
    HeaderSig { name: "httprouter", category: "Web Framework", header: "x-powered-by", pattern: "httprouter", version_prefix: "" },
    HeaderSig { name: "Kratos", category: "Web Framework", header: "x-powered-by", pattern: "kratos", version_prefix: "" },
    HeaderSig { name: "GoFrame", category: "Web Framework", header: "x-powered-by", pattern: "goframe", version_prefix: "" },
    HeaderSig { name: "GoFrame", category: "Web Framework", header: "server", pattern: "goframe", version_prefix: "" },
    HeaderSig { name: "Hertz", category: "Web Framework", header: "server", pattern: "hertz", version_prefix: "" },
    HeaderSig { name: "Macaron", category: "Web Framework", header: "x-powered-by", pattern: "macaron", version_prefix: "" },
    HeaderSig { name: "Flamingo", category: "Web Framework", header: "x-powered-by", pattern: "flamingo", version_prefix: "" },
    HeaderSig { name: "Goji", category: "Web Framework", header: "x-powered-by", pattern: "goji", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Orchard Core", category: "CMS", header: "x-powered-by", pattern: "orchard core", version_prefix: "" },
    HeaderSig { name: "Piranha CMS", category: "CMS", header: "x-powered-by", pattern: "piranha", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Squidex", category: "Headless CMS", header: "x-powered-by", pattern: "squidex", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Oqtane", category: "CMS", header: "x-powered-by", pattern: "oqtane", version_prefix: "" },
    HeaderSig { name: "Cofoundry", category: "CMS", header: "x-powered-by", pattern: "cofoundry", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "ABP Framework", category: "Web Framework", header: "x-powered-by", pattern: "abp", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Umbraco Heartcore", category: "Headless CMS", header: "x-powered-by", pattern: "umbraco heartcore", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Sitecore XM Cloud", category: "CMS", header: "x-powered-by", pattern: "sitecore xm", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "Apache Cassandra", category: "Database", header: "server", pattern: "apache cassandra", version_prefix: "" },
    HeaderSig { name: "Crate.io", category: "Database", header: "server", pattern: "crate", version_prefix: "" },
    HeaderSig { name: "CockroachDB", category: "Database", header: "server", pattern: "cockroachdb", version_prefix: "" },
    HeaderSig { name: "FoundationDB", category: "Database", header: "server", pattern: "foundationdb", version_prefix: "" },
    HeaderSig { name: "YugabyteDB", category: "Database", header: "server", pattern: "yugabytedb", version_prefix: "" },
    HeaderSig { name: "VoltDB", category: "Database", header: "server", pattern: "voltdb", version_prefix: "" },
    HeaderSig { name: "Timescale", category: "Database", header: "server", pattern: "timescaledb", version_prefix: "" },
    HeaderSig { name: "Apache Pinot", category: "Database", header: "server", pattern: "pinot", version_prefix: "" },
    HeaderSig { name: "Apache Ignite", category: "Database", header: "server", pattern: "ignite", version_prefix: "" },
    HeaderSig { name: "GridGain", category: "Database", header: "server", pattern: "gridgain", version_prefix: "" },
    HeaderSig { name: "Hazelcast", category: "Database", header: "server", pattern: "hazelcast", version_prefix: "" },
    HeaderSig { name: "Memgraph", category: "Database", header: "server", pattern: "memgraph", version_prefix: "" },
    HeaderSig { name: "JanusGraph", category: "Database", header: "server", pattern: "janusgraph", version_prefix: "" },
    HeaderSig { name: "TigerGraph", category: "Database", header: "server", pattern: "tigergraph", version_prefix: "" },
    HeaderSig { name: "Fauna", category: "Database", header: "server", pattern: "fauna", version_prefix: "" },
    HeaderSig { name: "Neon", category: "Database", header: "x-neon-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Turso", category: "Database", header: "server", pattern: "turso", version_prefix: "" },

    // -- API --
    HeaderSig { name: "Swagger", category: "API", header: "x-swagger-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "OpenAPI", category: "API", header: "x-openapi-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "tRPC", category: "API", header: "x-trpc-source", pattern: "", version_prefix: "" },
    HeaderSig { name: "gRPC", category: "API", header: "content-type", pattern: "application/grpc", version_prefix: "" },
    HeaderSig { name: "gRPC-Web", category: "API", header: "content-type", pattern: "application/grpc-web", version_prefix: "" },

    // -- GraphQL --
    HeaderSig { name: "Mercurius", category: "GraphQL", header: "x-powered-by", pattern: "mercurius", version_prefix: "" },
    HeaderSig { name: "Pothos", category: "GraphQL", header: "x-powered-by", pattern: "pothos", version_prefix: "" },
    HeaderSig { name: "Strawberry", category: "GraphQL", header: "x-powered-by", pattern: "strawberry", version_prefix: "" },
    HeaderSig { name: "Ariadne", category: "GraphQL", header: "x-powered-by", pattern: "ariadne", version_prefix: "" },
    HeaderSig { name: "Graphene", category: "GraphQL", header: "x-powered-by", pattern: "graphene", version_prefix: "" },
    HeaderSig { name: "Sangria", category: "GraphQL", header: "x-powered-by", pattern: "sangria", version_prefix: "" },
    HeaderSig { name: "Caliban", category: "GraphQL", header: "x-powered-by", pattern: "caliban", version_prefix: "" },
    HeaderSig { name: "Juniper", category: "GraphQL", header: "x-powered-by", pattern: "juniper", version_prefix: "" },
    HeaderSig { name: "async-graphql", category: "GraphQL", header: "x-powered-by", pattern: "async-graphql", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "Cloudflare R2", category: "Storage", header: "x-amz-cf-id", pattern: "", version_prefix: "" },

    // -- CDN --
    HeaderSig { name: "DigitalOcean CDN", category: "CDN", header: "server", pattern: "digitalocean", version_prefix: "" },
    HeaderSig { name: "OVH CDN", category: "CDN", header: "server", pattern: "ovh", version_prefix: "" },
    HeaderSig { name: "Hetzner", category: "CDN", header: "server", pattern: "hetzner", version_prefix: "" },
    HeaderSig { name: "Vultr", category: "CDN", header: "server", pattern: "vultr", version_prefix: "" },
    HeaderSig { name: "Linode", category: "CDN", header: "server", pattern: "linode", version_prefix: "" },
    HeaderSig { name: "Scaleway", category: "CDN", header: "server", pattern: "scaleway", version_prefix: "" },
    HeaderSig { name: "UpCloud", category: "CDN", header: "server", pattern: "upcloud", version_prefix: "" },
    HeaderSig { name: "Oracle Cloud", category: "CDN", header: "server", pattern: "oracle-cloud", version_prefix: "" },
    HeaderSig { name: "Alibaba Cloud CDN", category: "CDN", header: "server", pattern: "aliyun", version_prefix: "" },
    HeaderSig { name: "Tencent Cloud CDN", category: "CDN", header: "server", pattern: "tencent", version_prefix: "" },
    HeaderSig { name: "Baidu Cloud CDN", category: "CDN", header: "server", pattern: "baidu", version_prefix: "" },
    HeaderSig { name: "Yandex CDN", category: "CDN", header: "server", pattern: "yandex", version_prefix: "" },
    HeaderSig { name: "CacheFly", category: "CDN", header: "server", pattern: "cachefly", version_prefix: "" },
    HeaderSig { name: "Section.io", category: "CDN", header: "x-section-io", pattern: "", version_prefix: "" },
    HeaderSig { name: "GlobalSign", category: "CDN", header: "x-globalsign", pattern: "", version_prefix: "" },

    // -- Firewall --
    HeaderSig { name: "Sophos XG", category: "Firewall", header: "server", pattern: "sophos xg", version_prefix: "" },
    HeaderSig { name: "FortiGate", category: "Firewall", header: "server", pattern: "fortigate", version_prefix: "" },
    HeaderSig { name: "SonicWall", category: "Firewall", header: "server", pattern: "sonicwall", version_prefix: "" },
    HeaderSig { name: "WatchGuard", category: "Firewall", header: "server", pattern: "watchguard", version_prefix: "" },
    HeaderSig { name: "Untangle", category: "Firewall", header: "server", pattern: "untangle", version_prefix: "" },
    HeaderSig { name: "Endian", category: "Firewall", header: "server", pattern: "endian", version_prefix: "" },
    HeaderSig { name: "IPFire", category: "Firewall", header: "server", pattern: "ipfire", version_prefix: "" },
    HeaderSig { name: "Zentyal", category: "Firewall", header: "server", pattern: "zentyal", version_prefix: "" },
    HeaderSig { name: "ClearOS", category: "Firewall", header: "server", pattern: "clearos", version_prefix: "" },

    // -- Security --
    HeaderSig { name: "Wazuh", category: "Security", header: "x-wazuh-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "OSSEC", category: "Security", header: "server", pattern: "ossec", version_prefix: "" },
    HeaderSig { name: "Fail2ban", category: "Security", header: "x-fail2ban", pattern: "", version_prefix: "" },
    HeaderSig { name: "CrowdSec", category: "Security", header: "x-crowdsec-decision", pattern: "", version_prefix: "" },
    HeaderSig { name: "GreyNoise", category: "Security", header: "x-greynoise", pattern: "", version_prefix: "" },

    // -- Analytics --
    HeaderSig { name: "Apache Zeppelin", category: "Analytics", header: "server", pattern: "zeppelin", version_prefix: "" },
    HeaderSig { name: "Looker", category: "Analytics", header: "x-powered-by", pattern: "looker", version_prefix: "" },
    HeaderSig { name: "Sisense", category: "Analytics", header: "x-powered-by", pattern: "sisense", version_prefix: "" },
    HeaderSig { name: "Tableau", category: "Analytics", header: "x-powered-by", pattern: "tableau", version_prefix: "" },
    HeaderSig { name: "Power BI", category: "Analytics", header: "x-powered-by", pattern: "power bi", version_prefix: "" },
    HeaderSig { name: "Mode", category: "Analytics", header: "x-powered-by", pattern: "mode", version_prefix: "" },
    HeaderSig { name: "Preset", category: "Analytics", header: "server", pattern: "preset", version_prefix: "" },
    HeaderSig { name: "Lightdash", category: "Analytics", header: "server", pattern: "lightdash", version_prefix: "" },
    HeaderSig { name: "Cube.js", category: "Analytics", header: "x-powered-by", pattern: "cube.js", version_prefix: "" },

    // -- Automation --
    HeaderSig { name: "n8n", category: "Automation", header: "server", pattern: "n8n", version_prefix: "" },
    HeaderSig { name: "Huginn", category: "Automation", header: "x-powered-by", pattern: "huginn", version_prefix: "" },
    HeaderSig { name: "Automatisch", category: "Automation", header: "server", pattern: "automatisch", version_prefix: "" },
    HeaderSig { name: "Windmill", category: "Automation", header: "server", pattern: "windmill", version_prefix: "" },

    // -- Orchestration --
    HeaderSig { name: "Temporal", category: "Orchestration", header: "server", pattern: "temporal", version_prefix: "" },
    HeaderSig { name: "Prefect", category: "Orchestration", header: "server", pattern: "prefect", version_prefix: "" },
    HeaderSig { name: "Dagster", category: "Orchestration", header: "server", pattern: "dagster", version_prefix: "" },

    // -- Low-Code --
    HeaderSig { name: "Retool", category: "Low-Code", header: "x-powered-by", pattern: "retool", version_prefix: "" },
    HeaderSig { name: "Budibase", category: "Low-Code", header: "x-powered-by", pattern: "budibase", version_prefix: "" },
    HeaderSig { name: "Appsmith", category: "Low-Code", header: "x-powered-by", pattern: "appsmith", version_prefix: "" },
    HeaderSig { name: "ToolJet", category: "Low-Code", header: "x-powered-by", pattern: "tooljet", version_prefix: "" },
    HeaderSig { name: "NocoDB", category: "Low-Code", header: "x-powered-by", pattern: "nocodb", version_prefix: "" },
    HeaderSig { name: "Baserow", category: "Low-Code", header: "x-powered-by", pattern: "baserow", version_prefix: "" },

    // -- Hosting Panel --
    HeaderSig { name: "cPanel", category: "Hosting Panel", header: "server", pattern: "cpanel", version_prefix: "" },
    HeaderSig { name: "cPanel", category: "Hosting Panel", header: "set-cookie", pattern: "cpsession", version_prefix: "" },
    HeaderSig { name: "Plesk", category: "Hosting Panel", header: "server", pattern: "sw-cp-server", version_prefix: "" },
    HeaderSig { name: "Plesk", category: "Hosting Panel", header: "set-cookie", pattern: "plesk-session", version_prefix: "" },
    HeaderSig { name: "Webmin", category: "Hosting Panel", header: "server", pattern: "webmin", version_prefix: "" },
    HeaderSig { name: "ISPConfig", category: "Hosting Panel", header: "x-powered-by", pattern: "ispconfig", version_prefix: "" },
    HeaderSig { name: "CyberPanel", category: "Hosting Panel", header: "server", pattern: "cyberpanel", version_prefix: "" },
    HeaderSig { name: "VestaCP", category: "Hosting Panel", header: "server", pattern: "vestacp", version_prefix: "" },
    HeaderSig { name: "HestiaCP", category: "Hosting Panel", header: "server", pattern: "hestiacp", version_prefix: "" },
    HeaderSig { name: "Froxlor", category: "Hosting Panel", header: "x-powered-by", pattern: "froxlor", version_prefix: "" },
    HeaderSig { name: "CloudPanel", category: "Hosting Panel", header: "server", pattern: "cloudpanel", version_prefix: "" },
    HeaderSig { name: "RunCloud", category: "Hosting Panel", header: "x-powered-by", pattern: "runcloud", version_prefix: "" },
    HeaderSig { name: "GridPane", category: "Hosting Panel", header: "x-powered-by", pattern: "gridpane", version_prefix: "" },
    HeaderSig { name: "SpinupWP", category: "Hosting Panel", header: "x-powered-by", pattern: "spinupwp", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Snipcart", category: "eCommerce", header: "x-snipcart", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ecwid", category: "eCommerce", header: "set-cookie", pattern: "ecwid_", version_prefix: "" },
    HeaderSig { name: "Gumroad", category: "eCommerce", header: "x-powered-by", pattern: "gumroad", version_prefix: "" },
    HeaderSig { name: "Paddle", category: "eCommerce", header: "x-powered-by", pattern: "paddle", version_prefix: "" },
    HeaderSig { name: "Lemon Squeezy", category: "eCommerce", header: "x-powered-by", pattern: "lemonsqueezy", version_prefix: "" },
    HeaderSig { name: "Stripe Checkout", category: "eCommerce", header: "x-stripe-checkout", pattern: "", version_prefix: "" },
    HeaderSig { name: "Square", category: "eCommerce", header: "x-powered-by", pattern: "square", version_prefix: "" },
    HeaderSig { name: "Wix Stores", category: "eCommerce", header: "x-wix-stores", pattern: "", version_prefix: "" },
    HeaderSig { name: "Etsy", category: "eCommerce", header: "x-etsy-request-uuid", pattern: "", version_prefix: "" },
    HeaderSig { name: "Shopline", category: "eCommerce", header: "x-powered-by", pattern: "shopline", version_prefix: "" },
    HeaderSig { name: "Shoplazza", category: "eCommerce", header: "x-powered-by", pattern: "shoplazza", version_prefix: "" },
    HeaderSig { name: "VTEX", category: "eCommerce", header: "x-vtex-server", pattern: "", version_prefix: "" },
    HeaderSig { name: "VTEX", category: "eCommerce", header: "x-powered-by", pattern: "vtex", version_prefix: "" },

    // -- Search Engine --
    HeaderSig { name: "Algolia", category: "Search Engine", header: "x-algolia-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Algolia", category: "Search Engine", header: "x-algolia-api-key", pattern: "", version_prefix: "" },
    HeaderSig { name: "Sphinx", category: "Search Engine", header: "server", pattern: "sphinx", version_prefix: "" },
    HeaderSig { name: "Manticore Search", category: "Search Engine", header: "server", pattern: "manticore", version_prefix: "" },
    HeaderSig { name: "OpenSearch", category: "Search Engine", header: "server", pattern: "opensearch", version_prefix: "" },
    HeaderSig { name: "Vespa", category: "Search Engine", header: "server", pattern: "vespa", version_prefix: "" },
    HeaderSig { name: "Sonic", category: "Search Engine", header: "server", pattern: "sonic", version_prefix: "" },
    HeaderSig { name: "Zinc Search", category: "Search Engine", header: "server", pattern: "zincsearch", version_prefix: "" },
    HeaderSig { name: "Tantivy", category: "Search Engine", header: "server", pattern: "tantivy", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Shiny Server", category: "Web Framework", header: "server", pattern: "shiny-server", version_prefix: "" },
    HeaderSig { name: "Panel Server", category: "Web Framework", header: "server", pattern: "panel", version_prefix: "" },
    HeaderSig { name: "Voila Server", category: "Web Framework", header: "server", pattern: "voila", version_prefix: "" },
    HeaderSig { name: "Bokeh", category: "Web Framework", header: "server", pattern: "bokeh", version_prefix: "" },

    // -- Remote Access --
    HeaderSig { name: "Apache Guacamole", category: "Remote Access", header: "server", pattern: "guacamole", version_prefix: "" },
    HeaderSig { name: "Teleport", category: "Remote Access", header: "x-teleport-auth", pattern: "", version_prefix: "" },

    // -- VPN --
    HeaderSig { name: "Tailscale", category: "VPN", header: "server", pattern: "tailscale", version_prefix: "" },
    HeaderSig { name: "Headscale", category: "VPN", header: "server", pattern: "headscale", version_prefix: "" },
    HeaderSig { name: "WireGuard", category: "VPN", header: "server", pattern: "wireguard", version_prefix: "" },
    HeaderSig { name: "Pritunl", category: "VPN", header: "server", pattern: "pritunl", version_prefix: "" },
    HeaderSig { name: "OpenVPN", category: "VPN", header: "server", pattern: "openvpn", version_prefix: "" },

    // -- File Sharing --
    HeaderSig { name: "Nextcloud", category: "File Sharing", header: "x-nextcloud-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Nextcloud", category: "File Sharing", header: "set-cookie", pattern: "nc_session_id", version_prefix: "" },
    HeaderSig { name: "ownCloud", category: "File Sharing", header: "x-powered-by", pattern: "owncloud", version_prefix: "" },
    HeaderSig { name: "Seafile", category: "File Sharing", header: "server", pattern: "seafile", version_prefix: "" },
    HeaderSig { name: "FileRun", category: "File Sharing", header: "x-powered-by", pattern: "filerun", version_prefix: "" },

    // -- IDE --
    HeaderSig { name: "Gitpod", category: "IDE", header: "x-gitpod-workspace-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Coder", category: "IDE", header: "x-powered-by", pattern: "coder", version_prefix: "" },
    HeaderSig { name: "code-server", category: "IDE", header: "server", pattern: "code-server", version_prefix: "" },
    HeaderSig { name: "Theia", category: "IDE", header: "server", pattern: "theia", version_prefix: "" },

    // -- Search Engine --
    HeaderSig { name: "Apache Solr", category: "Search Engine", header: "server", pattern: "apache-solr", version_prefix: "" },
    HeaderSig { name: "Apache Lucene", category: "Search Engine", header: "server", pattern: "lucene", version_prefix: "" },

    // -- Background Jobs --
    HeaderSig { name: "Sidekiq", category: "Background Jobs", header: "x-powered-by", pattern: "sidekiq", version_prefix: "" },
    HeaderSig { name: "Celery", category: "Background Jobs", header: "x-powered-by", pattern: "celery", version_prefix: "" },
    HeaderSig { name: "Bull", category: "Background Jobs", header: "x-powered-by", pattern: "bull", version_prefix: "" },
    HeaderSig { name: "Faktory", category: "Background Jobs", header: "server", pattern: "faktory", version_prefix: "" },

    // -- Message Queue --
    HeaderSig { name: "Apache Pulsar", category: "Message Queue", header: "server", pattern: "pulsar", version_prefix: "" },
    HeaderSig { name: "NATS", category: "Message Queue", header: "server", pattern: "nats", version_prefix: "" },
    HeaderSig { name: "ZeroMQ", category: "Message Queue", header: "server", pattern: "zeromq", version_prefix: "" },
    HeaderSig { name: "Apache RocketMQ", category: "Message Queue", header: "server", pattern: "rocketmq", version_prefix: "" },

    // -- WebSocket --
    HeaderSig { name: "Centrifugo", category: "WebSocket", header: "server", pattern: "centrifugo", version_prefix: "" },
    HeaderSig { name: "Socket.io", category: "WebSocket", header: "x-powered-by", pattern: "socket.io", version_prefix: "" },
    HeaderSig { name: "Phoenix Channels", category: "WebSocket", header: "x-powered-by", pattern: "phoenix channels", version_prefix: "" },
    HeaderSig { name: "ActionCable", category: "WebSocket", header: "x-powered-by", pattern: "actioncable", version_prefix: "" },

    // -- CI/CD --
    HeaderSig { name: "GoCD", category: "CI/CD", header: "server", pattern: "gocd", version_prefix: "" },
    HeaderSig { name: "Buildkite", category: "CI/CD", header: "x-buildkite-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Woodpecker", category: "CI/CD", header: "server", pattern: "woodpecker", version_prefix: "" },
    HeaderSig { name: "Semaphore", category: "CI/CD", header: "x-powered-by", pattern: "semaphore", version_prefix: "" },
    HeaderSig { name: "Codefresh", category: "CI/CD", header: "x-powered-by", pattern: "codefresh", version_prefix: "" },
    HeaderSig { name: "Buddy CI", category: "CI/CD", header: "x-powered-by", pattern: "buddy", version_prefix: "" },

    // -- Code Search --
    HeaderSig { name: "Sourcegraph", category: "Code Search", header: "x-sourcegraph-request-id", pattern: "", version_prefix: "" },

    // -- AI --
    HeaderSig { name: "Cody", category: "AI", header: "x-powered-by", pattern: "cody", version_prefix: "" },
    HeaderSig { name: "Copilot", category: "AI", header: "x-github-copilot", pattern: "", version_prefix: "" },

    // -- ML Platform --
    HeaderSig { name: "Weights & Biases", category: "ML Platform", header: "server", pattern: "wandb", version_prefix: "" },
    HeaderSig { name: "Neptune.ai", category: "ML Platform", header: "server", pattern: "neptune", version_prefix: "" },
    HeaderSig { name: "DVC", category: "ML Platform", header: "server", pattern: "dvc", version_prefix: "" },
    HeaderSig { name: "Seldon", category: "ML Platform", header: "server", pattern: "seldon", version_prefix: "" },
    HeaderSig { name: "BentoML", category: "ML Platform", header: "server", pattern: "bentoml", version_prefix: "" },
    HeaderSig { name: "Ray Serve", category: "ML Platform", header: "server", pattern: "ray", version_prefix: "" },
    HeaderSig { name: "Triton", category: "ML Platform", header: "server", pattern: "triton", version_prefix: "" },
    HeaderSig { name: "TensorFlow Serving", category: "ML Platform", header: "server", pattern: "tensorflow", version_prefix: "" },
    HeaderSig { name: "TorchServe", category: "ML Platform", header: "server", pattern: "torchserve", version_prefix: "" },
    HeaderSig { name: "vLLM", category: "ML Platform", header: "server", pattern: "vllm", version_prefix: "" },
    HeaderSig { name: "Ollama", category: "ML Platform", header: "server", pattern: "ollama", version_prefix: "" },
    HeaderSig { name: "LM Studio", category: "ML Platform", header: "server", pattern: "lm-studio", version_prefix: "" },
    HeaderSig { name: "LocalAI", category: "ML Platform", header: "server", pattern: "localai", version_prefix: "" },
    HeaderSig { name: "Text Generation Inference", category: "ML Platform", header: "server", pattern: "tgi", version_prefix: "" },
    HeaderSig { name: "LiteLLM", category: "ML Platform", header: "server", pattern: "litellm", version_prefix: "" },

    // -- Orchestration --
    HeaderSig { name: "Cadence", category: "Orchestration", header: "server", pattern: "cadence", version_prefix: "" },

    // -- Serverless --
    HeaderSig { name: "Step Functions", category: "Serverless", header: "x-amz-executed-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "OpenWhisk", category: "Serverless", header: "x-openwhisk-activation-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Knative", category: "Serverless", header: "x-knative-serving", pattern: "", version_prefix: "" },
    HeaderSig { name: "Spin", category: "Serverless", header: "server", pattern: "spin", version_prefix: "" },

    // -- Runtime --
    HeaderSig { name: "Wasmtime", category: "Runtime", header: "server", pattern: "wasmtime", version_prefix: "" },
    HeaderSig { name: "Wasmer", category: "Runtime", header: "server", pattern: "wasmer", version_prefix: "" },

    // -- Serverless --
    HeaderSig { name: "Cloudflare Workers", category: "Serverless", header: "cf-worker", pattern: "", version_prefix: "" },
    HeaderSig { name: "Durable Objects", category: "Serverless", header: "x-do-id", pattern: "", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "Turso", category: "Database", header: "x-turso-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "D1", category: "Database", header: "x-d1-request-id", pattern: "", version_prefix: "" },

    // -- Storage --
    HeaderSig { name: "R2", category: "Storage", header: "x-r2-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "MinIO", category: "Storage", header: "x-minio-object-lock", pattern: "", version_prefix: "" },
    HeaderSig { name: "SeaweedFS", category: "Storage", header: "server", pattern: "seaweedfs", version_prefix: "" },
    HeaderSig { name: "LakeFS", category: "Storage", header: "server", pattern: "lakefs", version_prefix: "" },
    HeaderSig { name: "Delta Lake", category: "Storage", header: "server", pattern: "delta", version_prefix: "" },
    HeaderSig { name: "Apache Iceberg", category: "Storage", header: "server", pattern: "iceberg", version_prefix: "" },

    // -- Database --
    HeaderSig { name: "Weaviate", category: "Database", header: "server", pattern: "weaviate", version_prefix: "" },
    HeaderSig { name: "Qdrant", category: "Database", header: "server", pattern: "qdrant", version_prefix: "" },
    HeaderSig { name: "Milvus", category: "Database", header: "server", pattern: "milvus", version_prefix: "" },
    HeaderSig { name: "Pinecone", category: "Database", header: "x-pinecone-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Chroma", category: "Database", header: "server", pattern: "chroma", version_prefix: "" },
    HeaderSig { name: "pgvector", category: "Database", header: "server", pattern: "pgvector", version_prefix: "" },
    HeaderSig { name: "FAISS", category: "Database", header: "server", pattern: "faiss", version_prefix: "" },
    HeaderSig { name: "LanceDB", category: "Database", header: "server", pattern: "lancedb", version_prefix: "" },
    HeaderSig { name: "Zilliz", category: "Database", header: "server", pattern: "zilliz", version_prefix: "" },
    HeaderSig { name: "Upstash", category: "Database", header: "x-upstash-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Neon", category: "Database", header: "server", pattern: "neon", version_prefix: "" },
    // =========================================================================
    // EXPANDED SIGNATURES DATABASE PART 3 (190 additional entries)
    // =========================================================================

    // -- Proxy --
    HeaderSig { name: "WebSEAL", category: "Proxy", header: "server", pattern: "webseal", version_prefix: "" },

    // -- Cache --
    HeaderSig { name: "Varnish", category: "Cache", header: "server", pattern: "varnish", version_prefix: "" },

    // -- Proxy Server --
    HeaderSig { name: "Squid", category: "Proxy Server", header: "server", pattern: "squid/", version_prefix: "squid" },

    // -- Load Balancer --
    HeaderSig { name: "HAProxy", category: "Load Balancer", header: "x-haproxy-server-state", pattern: "", version_prefix: "" },

    // -- Proxy --
    HeaderSig { name: "ATS", category: "Proxy", header: "server", pattern: "ats", version_prefix: "" },
    HeaderSig { name: "Apache Traffic Server", category: "Proxy", header: "via", pattern: "apachets", version_prefix: "" },

    // -- Service Mesh --
    HeaderSig { name: "Istio", category: "Service Mesh", header: "x-envoy-peer-metadata", pattern: "", version_prefix: "" },
    HeaderSig { name: "Consul Connect", category: "Service Mesh", header: "x-consul-token", pattern: "", version_prefix: "" },

    // -- Proxy --
    HeaderSig { name: "Envoy", category: "Proxy", header: "x-envoy-attempt-count", pattern: "", version_prefix: "" },

    // -- Tunnel --
    HeaderSig { name: "Cloudflare Tunnel", category: "Tunnel", header: "cf-cloudflared-http-protocol", pattern: "", version_prefix: "" },
    HeaderSig { name: "LocalTunnel", category: "Tunnel", header: "server", pattern: "localtunnel", version_prefix: "" },
    HeaderSig { name: "PageKite", category: "Tunnel", header: "server", pattern: "pagekite", version_prefix: "" },
    HeaderSig { name: "Telebit", category: "Tunnel", header: "server", pattern: "telebit", version_prefix: "" },
    HeaderSig { name: "Bore", category: "Tunnel", header: "server", pattern: "bore", version_prefix: "" },
    HeaderSig { name: "Rathole", category: "Tunnel", header: "server", pattern: "rathole", version_prefix: "" },
    HeaderSig { name: "frp", category: "Tunnel", header: "server", pattern: "frp", version_prefix: "" },
    HeaderSig { name: "chisel", category: "Tunnel", header: "server", pattern: "chisel", version_prefix: "" },

    // -- PaaS --
    HeaderSig { name: "Cloudflare Pages", category: "PaaS", header: "cf-page", pattern: "", version_prefix: "" },
    HeaderSig { name: "Deta Space", category: "PaaS", header: "server", pattern: "deta", version_prefix: "" },
    HeaderSig { name: "Glitch", category: "PaaS", header: "x-powered-by", pattern: "glitch", version_prefix: "" },
    HeaderSig { name: "Replit", category: "PaaS", header: "x-replit-cluster", pattern: "", version_prefix: "" },
    HeaderSig { name: "CodeSandbox", category: "PaaS", header: "x-powered-by", pattern: "codesandbox", version_prefix: "" },
    HeaderSig { name: "StackBlitz", category: "PaaS", header: "x-powered-by", pattern: "stackblitz", version_prefix: "" },
    HeaderSig { name: "Platform.sh", category: "PaaS", header: "x-platform-server", pattern: "", version_prefix: "" },
    HeaderSig { name: "Clever Cloud", category: "PaaS", header: "x-powered-by", pattern: "clever-cloud", version_prefix: "" },
    HeaderSig { name: "Back4App", category: "PaaS", header: "x-powered-by", pattern: "back4app", version_prefix: "" },
    HeaderSig { name: "Koyeb", category: "PaaS", header: "server", pattern: "koyeb", version_prefix: "" },
    HeaderSig { name: "Northflank", category: "PaaS", header: "server", pattern: "northflank", version_prefix: "" },
    HeaderSig { name: "Porter", category: "PaaS", header: "server", pattern: "porter", version_prefix: "" },
    HeaderSig { name: "Aptible", category: "PaaS", header: "server", pattern: "aptible", version_prefix: "" },
    HeaderSig { name: "DigitalOcean App", category: "PaaS", header: "x-do-app-origin", pattern: "", version_prefix: "" },
    HeaderSig { name: "DigitalOcean App", category: "PaaS", header: "x-do-orig-status", pattern: "", version_prefix: "" },
    HeaderSig { name: "Google App Engine", category: "PaaS", header: "server", pattern: "google frontend", version_prefix: "" },
    HeaderSig { name: "Google App Engine", category: "PaaS", header: "x-appengine-resource-usage", pattern: "", version_prefix: "" },
    HeaderSig { name: "AWS Amplify", category: "PaaS", header: "x-amz-apigw-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Azure App Service", category: "PaaS", header: "x-ms-routing-name", pattern: "", version_prefix: "" },
    HeaderSig { name: "IBM Cloud", category: "PaaS", header: "x-powered-by", pattern: "ibm cloud", version_prefix: "" },
    HeaderSig { name: "SAP BTP", category: "PaaS", header: "x-powered-by", pattern: "sap btp", version_prefix: "" },

    // -- eCommerce --
    HeaderSig { name: "Magento 2", category: "eCommerce", header: "set-cookie", pattern: "mage-cache", version_prefix: "" },
    HeaderSig { name: "Magento 2", category: "eCommerce", header: "x-magento-tags", pattern: "", version_prefix: "" },
    HeaderSig { name: "Shopify Plus", category: "eCommerce", header: "x-shopify-custom", pattern: "", version_prefix: "" },
    HeaderSig { name: "Squarespace Commerce", category: "eCommerce", header: "x-squarespace-commerce", pattern: "", version_prefix: "" },
    HeaderSig { name: "Wix eCommerce", category: "eCommerce", header: "x-wix-commerce", pattern: "", version_prefix: "" },
    HeaderSig { name: "Webflow Ecommerce", category: "eCommerce", header: "x-webflow-ecommerce", pattern: "", version_prefix: "" },
    HeaderSig { name: "ThriveCart", category: "eCommerce", header: "x-powered-by", pattern: "thrivecart", version_prefix: "" },
    HeaderSig { name: "SamCart", category: "eCommerce", header: "x-powered-by", pattern: "samcart", version_prefix: "" },
    HeaderSig { name: "Kajabi", category: "eCommerce", header: "x-powered-by", pattern: "kajabi", version_prefix: "" },
    HeaderSig { name: "Teachable", category: "eCommerce", header: "x-powered-by", pattern: "teachable", version_prefix: "" },
    HeaderSig { name: "Thinkific", category: "eCommerce", header: "x-powered-by", pattern: "thinkific", version_prefix: "" },
    HeaderSig { name: "Podia", category: "eCommerce", header: "x-powered-by", pattern: "podia", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Duda", category: "CMS", header: "x-powered-by", pattern: "duda", version_prefix: "" },
    HeaderSig { name: "Weebly", category: "CMS", header: "x-powered-by", pattern: "weebly", version_prefix: "" },
    HeaderSig { name: "GoDaddy Website Builder", category: "CMS", header: "x-powered-by", pattern: "godaddy", version_prefix: "" },
    HeaderSig { name: "Strikingly", category: "CMS", header: "x-powered-by", pattern: "strikingly", version_prefix: "" },
    HeaderSig { name: "Carrd", category: "CMS", header: "server", pattern: "carrd", version_prefix: "" },
    HeaderSig { name: "Framer", category: "CMS", header: "x-framer-render-type", pattern: "", version_prefix: "" },
    HeaderSig { name: "Framer", category: "CMS", header: "server", pattern: "framer", version_prefix: "" },
    HeaderSig { name: "Webnode", category: "CMS", header: "x-powered-by", pattern: "webnode", version_prefix: "" },
    HeaderSig { name: "Jimdo", category: "CMS", header: "x-powered-by", pattern: "jimdo", version_prefix: "" },
    HeaderSig { name: "Site123", category: "CMS", header: "x-powered-by", pattern: "site123", version_prefix: "" },
    HeaderSig { name: "Tilda", category: "CMS", header: "x-powered-by", pattern: "tilda", version_prefix: "" },
    HeaderSig { name: "Readymag", category: "CMS", header: "x-powered-by", pattern: "readymag", version_prefix: "" },
    HeaderSig { name: "Cargo", category: "CMS", header: "x-powered-by", pattern: "cargo", version_prefix: "" },
    HeaderSig { name: "Format", category: "CMS", header: "x-powered-by", pattern: "format", version_prefix: "" },
    HeaderSig { name: "Pixpa", category: "CMS", header: "x-powered-by", pattern: "pixpa", version_prefix: "" },
    HeaderSig { name: "Portfoliobox", category: "CMS", header: "x-powered-by", pattern: "portfoliobox", version_prefix: "" },
    HeaderSig { name: "SmugMug", category: "CMS", header: "x-powered-by", pattern: "smugmug", version_prefix: "" },
    HeaderSig { name: "Zenfolio", category: "CMS", header: "x-powered-by", pattern: "zenfolio", version_prefix: "" },
    HeaderSig { name: "Showit", category: "CMS", header: "x-powered-by", pattern: "showit", version_prefix: "" },
    HeaderSig { name: "Zyro", category: "CMS", header: "x-powered-by", pattern: "zyro", version_prefix: "" },

    // -- Marketing --
    HeaderSig { name: "HubSpot", category: "Marketing", header: "x-hs-request-id", pattern: "", version_prefix: "" },

    // -- CRM --
    HeaderSig { name: "Salesforce", category: "CRM", header: "x-sfdc-request-id", pattern: "", version_prefix: "" },

    // -- Marketing --
    HeaderSig { name: "Marketo", category: "Marketing", header: "x-powered-by", pattern: "marketo", version_prefix: "" },
    HeaderSig { name: "Pardot", category: "Marketing", header: "x-powered-by", pattern: "pardot", version_prefix: "" },
    HeaderSig { name: "ActiveCampaign", category: "Marketing", header: "x-powered-by", pattern: "activecampaign", version_prefix: "" },
    HeaderSig { name: "Drip", category: "Marketing", header: "x-powered-by", pattern: "drip", version_prefix: "" },
    HeaderSig { name: "Mailchimp", category: "Marketing", header: "x-powered-by", pattern: "mailchimp", version_prefix: "" },
    HeaderSig { name: "Klaviyo", category: "Marketing", header: "x-powered-by", pattern: "klaviyo", version_prefix: "" },
    HeaderSig { name: "Braze", category: "Marketing", header: "x-powered-by", pattern: "braze", version_prefix: "" },

    // -- Support --
    HeaderSig { name: "Intercom", category: "Support", header: "x-intercom-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Zendesk", category: "Support", header: "x-zendesk-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Zendesk", category: "Support", header: "set-cookie", pattern: "_zendesk_session", version_prefix: "" },
    HeaderSig { name: "Freshdesk", category: "Support", header: "x-powered-by", pattern: "freshdesk", version_prefix: "" },
    HeaderSig { name: "Help Scout", category: "Support", header: "x-powered-by", pattern: "helpscout", version_prefix: "" },
    HeaderSig { name: "Crisp", category: "Support", header: "x-crisp-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Tawk.to", category: "Support", header: "x-powered-by", pattern: "tawk", version_prefix: "" },
    HeaderSig { name: "LiveChat", category: "Support", header: "x-powered-by", pattern: "livechat", version_prefix: "" },
    HeaderSig { name: "Drift", category: "Support", header: "x-powered-by", pattern: "drift", version_prefix: "" },

    // -- Serverless --
    HeaderSig { name: "Netlify Edge Functions", category: "Serverless", header: "x-nf-edge", pattern: "", version_prefix: "" },
    HeaderSig { name: "Vercel Edge", category: "Serverless", header: "x-matched-path", pattern: "", version_prefix: "" },

    // -- AI --
    HeaderSig { name: "Cloudflare Workers AI", category: "AI", header: "x-ai-model", pattern: "", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Deno Fresh", category: "Web Framework", header: "server", pattern: "deno/fresh", version_prefix: "" },

    // -- Serverless --
    HeaderSig { name: "Lagon", category: "Serverless", header: "server", pattern: "lagon", version_prefix: "" },
    HeaderSig { name: "Fermyon", category: "Serverless", header: "server", pattern: "fermyon", version_prefix: "" },
    HeaderSig { name: "Shuttle", category: "Serverless", header: "server", pattern: "shuttle", version_prefix: "" },
    HeaderSig { name: "Modal", category: "Serverless", header: "server", pattern: "modal", version_prefix: "" },

    // -- ML Platform --
    HeaderSig { name: "Banana.dev", category: "ML Platform", header: "server", pattern: "banana", version_prefix: "" },
    HeaderSig { name: "Replicate", category: "ML Platform", header: "x-replicate-prediction-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hugging Face", category: "ML Platform", header: "x-powered-by", pattern: "hugging face", version_prefix: "" },
    HeaderSig { name: "RunPod", category: "ML Platform", header: "server", pattern: "runpod", version_prefix: "" },
    HeaderSig { name: "Lambda Labs", category: "ML Platform", header: "server", pattern: "lambda", version_prefix: "" },
    HeaderSig { name: "Anyscale", category: "ML Platform", header: "server", pattern: "anyscale", version_prefix: "" },
    HeaderSig { name: "Baseten", category: "ML Platform", header: "server", pattern: "baseten", version_prefix: "" },
    HeaderSig { name: "Cerebrium", category: "ML Platform", header: "server", pattern: "cerebrium", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Honeycomb", category: "Monitoring", header: "x-honeycomb-team", pattern: "", version_prefix: "" },
    HeaderSig { name: "Lightstep", category: "Monitoring", header: "x-lightstep-access-token", pattern: "", version_prefix: "" },
    HeaderSig { name: "Instana", category: "Monitoring", header: "x-instana-t", pattern: "", version_prefix: "" },
    HeaderSig { name: "AppSignal", category: "Monitoring", header: "x-appsignal-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Scout APM", category: "Monitoring", header: "x-scout-transaction-id", pattern: "", version_prefix: "" },

    // -- Log Management --
    HeaderSig { name: "Logz.io", category: "Log Management", header: "x-logzio-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Coralogix", category: "Log Management", header: "x-powered-by", pattern: "coralogix", version_prefix: "" },
    HeaderSig { name: "Axiom", category: "Log Management", header: "x-axiom-request-id", pattern: "", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Betterstack", category: "Monitoring", header: "x-betterstack-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Cronitor", category: "Monitoring", header: "x-cronitor-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Checkly", category: "Monitoring", header: "x-checkly-request-id", pattern: "", version_prefix: "" },

    // -- Testing --
    HeaderSig { name: "Playwright", category: "Testing", header: "x-playwright-test", pattern: "", version_prefix: "" },
    HeaderSig { name: "Cypress", category: "Testing", header: "x-cypress-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Selenium", category: "Testing", header: "x-selenium-request", pattern: "", version_prefix: "" },
    HeaderSig { name: "k6", category: "Testing", header: "x-k6-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Locust", category: "Testing", header: "x-powered-by", pattern: "locust", version_prefix: "" },
    HeaderSig { name: "Gatling", category: "Testing", header: "x-powered-by", pattern: "gatling", version_prefix: "" },
    HeaderSig { name: "Artillery", category: "Testing", header: "x-powered-by", pattern: "artillery", version_prefix: "" },

    // -- Payment --
    HeaderSig { name: "Stripe", category: "Payment", header: "x-stripe-routing-context-priority-tier", pattern: "", version_prefix: "" },
    HeaderSig { name: "Adyen", category: "Payment", header: "x-powered-by", pattern: "adyen", version_prefix: "" },
    HeaderSig { name: "Braintree", category: "Payment", header: "x-powered-by", pattern: "braintree", version_prefix: "" },
    HeaderSig { name: "PayPal", category: "Payment", header: "x-powered-by", pattern: "paypal", version_prefix: "" },
    HeaderSig { name: "Razorpay", category: "Payment", header: "x-powered-by", pattern: "razorpay", version_prefix: "" },
    HeaderSig { name: "Mollie", category: "Payment", header: "x-powered-by", pattern: "mollie", version_prefix: "" },
    HeaderSig { name: "GoCardless", category: "Payment", header: "x-powered-by", pattern: "gocardless", version_prefix: "" },

    // -- Fintech --
    HeaderSig { name: "Plaid", category: "Fintech", header: "x-plaid-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Dwolla", category: "Fintech", header: "x-powered-by", pattern: "dwolla", version_prefix: "" },

    // -- Analytics --
    HeaderSig { name: "Google Tag Manager", category: "Analytics", header: "x-gtm-server", pattern: "", version_prefix: "" },
    HeaderSig { name: "Segment", category: "Analytics", header: "x-segment-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Amplitude", category: "Analytics", header: "x-amplitude-server-upload-time", pattern: "", version_prefix: "" },
    HeaderSig { name: "Mixpanel", category: "Analytics", header: "x-powered-by", pattern: "mixpanel", version_prefix: "" },
    HeaderSig { name: "Heap", category: "Analytics", header: "x-powered-by", pattern: "heap", version_prefix: "" },
    HeaderSig { name: "FullStory", category: "Analytics", header: "x-fullstory-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "LogRocket", category: "Analytics", header: "x-logrocket-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "PostHog", category: "Analytics", header: "x-posthog-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Umami", category: "Analytics", header: "x-powered-by", pattern: "umami", version_prefix: "" },
    HeaderSig { name: "Fathom", category: "Analytics", header: "x-powered-by", pattern: "fathom", version_prefix: "" },
    HeaderSig { name: "Simple Analytics", category: "Analytics", header: "x-powered-by", pattern: "simple analytics", version_prefix: "" },
    HeaderSig { name: "GoatCounter", category: "Analytics", header: "x-powered-by", pattern: "goatcounter", version_prefix: "" },
    HeaderSig { name: "Countly", category: "Analytics", header: "x-powered-by", pattern: "countly", version_prefix: "" },
    HeaderSig { name: "Pirsch", category: "Analytics", header: "x-powered-by", pattern: "pirsch", version_prefix: "" },
    HeaderSig { name: "Ackee", category: "Analytics", header: "x-powered-by", pattern: "ackee", version_prefix: "" },
    HeaderSig { name: "Open Web Analytics", category: "Analytics", header: "x-powered-by", pattern: "owa", version_prefix: "" },
    HeaderSig { name: "Clicky", category: "Analytics", header: "x-powered-by", pattern: "clicky", version_prefix: "" },
    HeaderSig { name: "Chartbeat", category: "Analytics", header: "x-powered-by", pattern: "chartbeat", version_prefix: "" },
    HeaderSig { name: "Parse.ly", category: "Analytics", header: "x-powered-by", pattern: "parsely", version_prefix: "" },

    // -- Personalization --
    HeaderSig { name: "Adobe Target", category: "Personalization", header: "x-powered-by", pattern: "adobe target", version_prefix: "" },

    // -- Feature Flags --
    HeaderSig { name: "LaunchDarkly", category: "Feature Flags", header: "x-launchdarkly-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Unleash", category: "Feature Flags", header: "x-unleash-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Split.io", category: "Feature Flags", header: "x-split-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Flagsmith", category: "Feature Flags", header: "x-powered-by", pattern: "flagsmith", version_prefix: "" },
    HeaderSig { name: "ConfigCat", category: "Feature Flags", header: "x-powered-by", pattern: "configcat", version_prefix: "" },
    HeaderSig { name: "DevCycle", category: "Feature Flags", header: "x-powered-by", pattern: "devcycle", version_prefix: "" },
    HeaderSig { name: "GrowthBook", category: "Feature Flags", header: "x-powered-by", pattern: "growthbook", version_prefix: "" },
    HeaderSig { name: "Statsig", category: "Feature Flags", header: "x-statsig-request-id", pattern: "", version_prefix: "" },

    // -- Messaging --
    HeaderSig { name: "Slack", category: "Messaging", header: "x-slack-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Microsoft Teams", category: "Messaging", header: "x-ms-teams-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Discord", category: "Messaging", header: "x-discord-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Matrix", category: "Messaging", header: "server", pattern: "matrix", version_prefix: "" },
    HeaderSig { name: "Element", category: "Messaging", header: "x-powered-by", pattern: "element", version_prefix: "" },
    HeaderSig { name: "Zulip", category: "Messaging", header: "x-powered-by", pattern: "zulip", version_prefix: "" },
    HeaderSig { name: "Rocket.Chat", category: "Messaging", header: "set-cookie", pattern: "rc_", version_prefix: "" },
    HeaderSig { name: "Mattermost", category: "Messaging", header: "set-cookie", pattern: "mattermost", version_prefix: "" },
    HeaderSig { name: "Chatwoot", category: "Messaging", header: "x-powered-by", pattern: "chatwoot", version_prefix: "" },
    HeaderSig { name: "Gitter", category: "Messaging", header: "x-powered-by", pattern: "gitter", version_prefix: "" },

    // -- CMS --
    HeaderSig { name: "Ghost", category: "CMS", header: "x-ghost-version", pattern: "", version_prefix: "" },
    HeaderSig { name: "Strapi", category: "CMS", header: "x-strapi-config", pattern: "", version_prefix: "" },
    HeaderSig { name: "Directus", category: "CMS", header: "x-directus-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Payload CMS", category: "CMS", header: "x-payload-request-id", pattern: "", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Sanity", category: "Headless CMS", header: "x-sanity-project-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Contentful", category: "Headless CMS", header: "x-contentful-environment", pattern: "", version_prefix: "" },
    HeaderSig { name: "Storyblok", category: "Headless CMS", header: "x-storyblok-space", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hygraph", category: "Headless CMS", header: "x-powered-by", pattern: "hygraph", version_prefix: "" },
    HeaderSig { name: "Strapi Cloud", category: "Headless CMS", header: "x-powered-by", pattern: "strapi cloud", version_prefix: "" },
    HeaderSig { name: "Payload Cloud", category: "Headless CMS", header: "x-powered-by", pattern: "payload cloud", version_prefix: "" },
    HeaderSig { name: "Builder.io", category: "Headless CMS", header: "x-powered-by", pattern: "builder.io", version_prefix: "" },
    HeaderSig { name: "Plasmic", category: "Headless CMS", header: "x-powered-by", pattern: "plasmic", version_prefix: "" },

    // -- Web Framework --
    HeaderSig { name: "Flask", category: "Web Framework", header: "set-cookie", pattern: "session=ey", version_prefix: "" },
    HeaderSig { name: "Django", category: "Web Framework", header: "set-cookie", pattern: "csrftoken", version_prefix: "" },
    HeaderSig { name: "Django", category: "Web Framework", header: "set-cookie", pattern: "sessionid", version_prefix: "" },
    HeaderSig { name: "Express Session", category: "Web Framework", header: "set-cookie", pattern: "connect.sid", version_prefix: "" },
    HeaderSig { name: "FastAPI", category: "Web Framework", header: "set-cookie", pattern: "fastapi_session", version_prefix: "" },
    HeaderSig { name: "Spring", category: "Web Framework", header: "set-cookie", pattern: "jsessionid", version_prefix: "" },
    HeaderSig { name: "Phoenix", category: "Web Framework", header: "set-cookie", pattern: "_csrf_token", version_prefix: "" },
    HeaderSig { name: "Play Framework", category: "Web Framework", header: "set-cookie", pattern: "play_session", version_prefix: "" },
    HeaderSig { name: "Gin", category: "Web Framework", header: "set-cookie", pattern: "gin_session", version_prefix: "" },
    // =========================================================================
    // EXPANDED SIGNATURES DATABASE PART 4 (98 additional entries)
    // =========================================================================

    // -- Web Server --
    HeaderSig { name: "Tengine", category: "Web Server", header: "server", pattern: "tengine/", version_prefix: "tengine" },
    HeaderSig { name: "EasyEngine", category: "Web Server", header: "x-powered-by", pattern: "easyengine", version_prefix: "" },
    HeaderSig { name: "Litespeed Enterprise", category: "Web Server", header: "server", pattern: "lsws", version_prefix: "lsws" },
    HeaderSig { name: "Apache-SSL", category: "Web Server", header: "server", pattern: "apache-ssl", version_prefix: "" },
    HeaderSig { name: "Nginx Unit", category: "Web Server", header: "server", pattern: "unit", version_prefix: "" },
    HeaderSig { name: "Angie PRO", category: "Web Server", header: "server", pattern: "angie-pro", version_prefix: "" },
    HeaderSig { name: "Caddy 2", category: "Web Server", header: "server", pattern: "caddy/2", version_prefix: "caddy" },
    HeaderSig { name: "Microsoft HTTPAPI 2.0", category: "Web Server", header: "server", pattern: "microsoft-httpapi/2.0", version_prefix: "microsoft-httpapi" },
    HeaderSig { name: "thttpd", category: "Web Server", header: "server", pattern: "thttpd/", version_prefix: "thttpd" },
    HeaderSig { name: "Jetty", category: "Web Server", header: "server", pattern: "jetty/", version_prefix: "jetty" },

    // -- Web Framework --
    HeaderSig { name: "Ruby on Rails", category: "Web Framework", header: "set-cookie", pattern: "_session_id", version_prefix: "" },
    HeaderSig { name: "Sinatra", category: "Web Framework", header: "set-cookie", pattern: "rack.session", version_prefix: "" },
    HeaderSig { name: "CakePHP 4", category: "Web Framework", header: "set-cookie", pattern: "csrftoken", version_prefix: "" },
    HeaderSig { name: "Yii 2", category: "Web Framework", header: "set-cookie", pattern: "_csrf", version_prefix: "" },
    HeaderSig { name: "Laravel Sanctum", category: "Web Framework", header: "set-cookie", pattern: "laravel_token", version_prefix: "" },
    HeaderSig { name: "Symfony Session", category: "Web Framework", header: "set-cookie", pattern: "symfony", version_prefix: "" },
    HeaderSig { name: "Tornado Session", category: "Web Framework", header: "set-cookie", pattern: "_xsrf", version_prefix: "" },
    HeaderSig { name: "Beego Session", category: "Web Framework", header: "set-cookie", pattern: "beegosessionid", version_prefix: "" },
    HeaderSig { name: "ThinkPHP Session", category: "Web Framework", header: "set-cookie", pattern: "think_session", version_prefix: "" },

    // -- Programming Language --
    HeaderSig { name: "Python", category: "Programming Language", header: "server", pattern: "python", version_prefix: "" },
    HeaderSig { name: "Python", category: "Programming Language", header: "x-powered-by", pattern: "python", version_prefix: "" },
    HeaderSig { name: "Ruby", category: "Programming Language", header: "x-powered-by", pattern: "ruby", version_prefix: "" },
    HeaderSig { name: "Lua", category: "Programming Language", header: "x-powered-by", pattern: "lua", version_prefix: "" },
    HeaderSig { name: "Go", category: "Programming Language", header: "x-powered-by", pattern: "golang", version_prefix: "" },
    HeaderSig { name: "Rust", category: "Programming Language", header: "x-powered-by", pattern: "rust", version_prefix: "" },
    HeaderSig { name: "Elixir", category: "Programming Language", header: "x-powered-by", pattern: "elixir", version_prefix: "" },
    HeaderSig { name: "Erlang", category: "Programming Language", header: "x-powered-by", pattern: "erlang", version_prefix: "" },
    HeaderSig { name: "Scala", category: "Programming Language", header: "x-powered-by", pattern: "scala", version_prefix: "" },
    HeaderSig { name: "Kotlin", category: "Programming Language", header: "x-powered-by", pattern: "kotlin", version_prefix: "" },
    HeaderSig { name: "Swift", category: "Programming Language", header: "x-powered-by", pattern: "swift", version_prefix: "" },
    HeaderSig { name: "Dart", category: "Programming Language", header: "x-powered-by", pattern: "dart", version_prefix: "" },
    HeaderSig { name: "Haskell", category: "Programming Language", header: "x-powered-by", pattern: "haskell", version_prefix: "" },
    HeaderSig { name: "Clojure", category: "Programming Language", header: "x-powered-by", pattern: "clojure", version_prefix: "" },
    HeaderSig { name: "F#", category: "Programming Language", header: "x-powered-by", pattern: "fsharp", version_prefix: "" },
    HeaderSig { name: "OCaml", category: "Programming Language", header: "x-powered-by", pattern: "ocaml", version_prefix: "" },
    HeaderSig { name: "Nim", category: "Programming Language", header: "x-powered-by", pattern: "nim", version_prefix: "" },
    HeaderSig { name: "Zig", category: "Programming Language", header: "x-powered-by", pattern: "zig", version_prefix: "" },
    HeaderSig { name: "Crystal", category: "Programming Language", header: "x-powered-by", pattern: "crystal", version_prefix: "" },
    HeaderSig { name: "V", category: "Programming Language", header: "x-powered-by", pattern: "vlang", version_prefix: "" },
    HeaderSig { name: "D", category: "Programming Language", header: "x-powered-by", pattern: "dlang", version_prefix: "" },

    // -- Headless CMS --
    HeaderSig { name: "Forestry", category: "Headless CMS", header: "x-powered-by", pattern: "forestry", version_prefix: "" },
    HeaderSig { name: "CloudCannon", category: "Headless CMS", header: "x-powered-by", pattern: "cloudcannon", version_prefix: "" },
    HeaderSig { name: "Decap CMS", category: "Headless CMS", header: "x-powered-by", pattern: "decap", version_prefix: "" },
    HeaderSig { name: "KeystoneJS 6", category: "Headless CMS", header: "x-powered-by", pattern: "keystone-6", version_prefix: "" },
    HeaderSig { name: "Directus Cloud", category: "Headless CMS", header: "x-powered-by", pattern: "directus cloud", version_prefix: "" },
    HeaderSig { name: "GraphCMS", category: "Headless CMS", header: "x-powered-by", pattern: "graphcms", version_prefix: "" },
    HeaderSig { name: "Caisy", category: "Headless CMS", header: "x-powered-by", pattern: "caisy", version_prefix: "" },
    HeaderSig { name: "Kontent.ai", category: "Headless CMS", header: "x-powered-by", pattern: "kontent", version_prefix: "" },

    // -- Static Site Generator --
    HeaderSig { name: "Hugo", category: "Static Site Generator", header: "x-generator", pattern: "hugo", version_prefix: "" },
    HeaderSig { name: "Jekyll", category: "Static Site Generator", header: "x-generator", pattern: "jekyll", version_prefix: "" },
    HeaderSig { name: "Hexo", category: "Static Site Generator", header: "x-generator", pattern: "hexo", version_prefix: "" },
    HeaderSig { name: "Eleventy", category: "Static Site Generator", header: "x-generator", pattern: "eleventy", version_prefix: "" },
    HeaderSig { name: "Pelican", category: "Static Site Generator", header: "x-generator", pattern: "pelican", version_prefix: "" },
    HeaderSig { name: "Gatsby", category: "Static Site Generator", header: "x-generator", pattern: "gatsby", version_prefix: "" },
    HeaderSig { name: "Next.js", category: "Static Site Generator", header: "x-generator", pattern: "next.js", version_prefix: "" },
    HeaderSig { name: "Nuxt", category: "Static Site Generator", header: "x-generator", pattern: "nuxt", version_prefix: "" },
    HeaderSig { name: "Astro", category: "Static Site Generator", header: "x-generator", pattern: "astro", version_prefix: "" },
    HeaderSig { name: "SvelteKit", category: "Static Site Generator", header: "x-generator", pattern: "sveltekit", version_prefix: "" },
    HeaderSig { name: "Gridsome", category: "Static Site Generator", header: "x-generator", pattern: "gridsome", version_prefix: "" },
    HeaderSig { name: "VitePress", category: "Static Site Generator", header: "x-powered-by", pattern: "vitepress", version_prefix: "" },
    HeaderSig { name: "Lume", category: "Static Site Generator", header: "x-powered-by", pattern: "lume", version_prefix: "" },
    HeaderSig { name: "Zola", category: "Static Site Generator", header: "x-powered-by", pattern: "zola", version_prefix: "" },
    HeaderSig { name: "Bridgetown", category: "Static Site Generator", header: "x-powered-by", pattern: "bridgetown", version_prefix: "" },

    // -- Monitoring --
    HeaderSig { name: "Node Exporter", category: "Monitoring", header: "server", pattern: "node_exporter", version_prefix: "" },
    HeaderSig { name: "Blackbox Exporter", category: "Monitoring", header: "server", pattern: "blackbox_exporter", version_prefix: "" },
    HeaderSig { name: "cAdvisor", category: "Monitoring", header: "server", pattern: "cadvisor", version_prefix: "" },
    HeaderSig { name: "Alertmanager", category: "Monitoring", header: "server", pattern: "alertmanager", version_prefix: "" },
    HeaderSig { name: "Pushgateway", category: "Monitoring", header: "server", pattern: "pushgateway", version_prefix: "" },
    HeaderSig { name: "Thanos Querier", category: "Monitoring", header: "server", pattern: "thanos-querier", version_prefix: "" },
    HeaderSig { name: "Cortex", category: "Monitoring", header: "server", pattern: "cortex", version_prefix: "" },
    HeaderSig { name: "Mimir", category: "Monitoring", header: "server", pattern: "mimir", version_prefix: "" },
    HeaderSig { name: "Tempo", category: "Monitoring", header: "server", pattern: "tempo", version_prefix: "" },

    // -- Game Server --
    HeaderSig { name: "Source Engine", category: "Game Server", header: "server", pattern: "source engine", version_prefix: "" },
    HeaderSig { name: "Unreal Engine", category: "Game Server", header: "server", pattern: "unreal", version_prefix: "" },
    HeaderSig { name: "Unity", category: "Game Server", header: "server", pattern: "unity", version_prefix: "" },
    HeaderSig { name: "Godot", category: "Game Server", header: "server", pattern: "godot", version_prefix: "" },
    HeaderSig { name: "Photon", category: "Game Server", header: "server", pattern: "photon", version_prefix: "" },
    HeaderSig { name: "PlayFab", category: "Game Server", header: "x-playfab-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Nakama", category: "Game Server", header: "server", pattern: "nakama", version_prefix: "" },
    HeaderSig { name: "Colyseus", category: "Game Server", header: "server", pattern: "colyseus", version_prefix: "" },
    HeaderSig { name: "Mirror", category: "Game Server", header: "server", pattern: "mirror", version_prefix: "" },

    // -- Decentralized --
    HeaderSig { name: "IPFS", category: "Decentralized", header: "server", pattern: "ipfs", version_prefix: "" },
    HeaderSig { name: "IPFS Gateway", category: "Decentralized", header: "x-ipfs-gateway", pattern: "", version_prefix: "" },
    HeaderSig { name: "Arweave", category: "Decentralized", header: "server", pattern: "arweave", version_prefix: "" },
    HeaderSig { name: "The Graph", category: "Decentralized", header: "x-powered-by", pattern: "the-graph", version_prefix: "" },

    // -- Web3 --
    HeaderSig { name: "Infura", category: "Web3", header: "x-infura-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Alchemy", category: "Web3", header: "x-alchemy-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "QuickNode", category: "Web3", header: "x-powered-by", pattern: "quicknode", version_prefix: "" },
    HeaderSig { name: "Moralis", category: "Web3", header: "x-powered-by", pattern: "moralis", version_prefix: "" },
    HeaderSig { name: "Thirdweb", category: "Web3", header: "x-powered-by", pattern: "thirdweb", version_prefix: "" },

    // -- Ingress --
    HeaderSig { name: "Kubernetes Ingress NGINX", category: "Ingress", header: "x-kubernetes-ingress", pattern: "", version_prefix: "" },
    HeaderSig { name: "Traefik Ingress", category: "Ingress", header: "x-traefik-router", pattern: "", version_prefix: "" },
    HeaderSig { name: "HAProxy Ingress", category: "Ingress", header: "x-haproxy-frontend", pattern: "", version_prefix: "" },
    HeaderSig { name: "Contour", category: "Ingress", header: "x-contour-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Emissary", category: "Ingress", header: "x-emissary-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Skipper", category: "Ingress", header: "x-skipper-route", pattern: "", version_prefix: "" },

    // -- Networking --
    HeaderSig { name: "Cilium", category: "Networking", header: "x-cilium-proxy", pattern: "", version_prefix: "" },
    HeaderSig { name: "Calico", category: "Networking", header: "x-calico-proxy", pattern: "", version_prefix: "" },
    // =========================================================================
    // EXPANDED SIGNATURES DATABASE PART 5 (35 additional entries)
    // =========================================================================

    // -- Search Engine --
    HeaderSig { name: "OpenSearch", category: "Search Engine", header: "x-opensearch-request-id", pattern: "", version_prefix: "" },

    // -- Data Processing --
    HeaderSig { name: "Apache Tika", category: "Data Processing", header: "server", pattern: "tika", version_prefix: "" },

    // -- Search Engine --
    HeaderSig { name: "Apache Solr", category: "Search Engine", header: "x-solr-qtime", pattern: "", version_prefix: "" },

    // -- Build Tool --
    HeaderSig { name: "Vite", category: "Build Tool", header: "x-powered-by", pattern: "vite", version_prefix: "" },
    HeaderSig { name: "Webpack Dev Server", category: "Build Tool", header: "x-powered-by", pattern: "webpack-dev-server", version_prefix: "" },
    HeaderSig { name: "Parcel", category: "Build Tool", header: "x-powered-by", pattern: "parcel", version_prefix: "" },
    HeaderSig { name: "Turbopack", category: "Build Tool", header: "x-powered-by", pattern: "turbopack", version_prefix: "" },
    HeaderSig { name: "esbuild", category: "Build Tool", header: "x-powered-by", pattern: "esbuild", version_prefix: "" },
    HeaderSig { name: "Rollup", category: "Build Tool", header: "x-powered-by", pattern: "rollup", version_prefix: "" },
    HeaderSig { name: "Snowpack", category: "Build Tool", header: "x-powered-by", pattern: "snowpack", version_prefix: "" },
    HeaderSig { name: "Rspack", category: "Build Tool", header: "x-powered-by", pattern: "rspack", version_prefix: "" },
    HeaderSig { name: "Biome", category: "Build Tool", header: "x-powered-by", pattern: "biome", version_prefix: "" },
    HeaderSig { name: "Farm", category: "Build Tool", header: "x-powered-by", pattern: "farm", version_prefix: "" },
    HeaderSig { name: "Bun Build", category: "Build Tool", header: "x-powered-by", pattern: "bun", version_prefix: "" },

    // -- WebSocket --
    HeaderSig { name: "Socket.io", category: "WebSocket", header: "server", pattern: "socket.io", version_prefix: "" },
    HeaderSig { name: "ws", category: "WebSocket", header: "server", pattern: "ws", version_prefix: "" },
    HeaderSig { name: "uWebSockets", category: "WebSocket", header: "server", pattern: "uwebsockets", version_prefix: "" },
    HeaderSig { name: "Gorilla WebSocket", category: "WebSocket", header: "x-powered-by", pattern: "gorilla/websocket", version_prefix: "" },
    HeaderSig { name: "Centrifugo", category: "WebSocket", header: "x-centrifugo", pattern: "", version_prefix: "" },
    HeaderSig { name: "Soketi", category: "WebSocket", header: "server", pattern: "soketi", version_prefix: "" },
    HeaderSig { name: "Pusher", category: "WebSocket", header: "x-pusher-channels", pattern: "", version_prefix: "" },
    HeaderSig { name: "Ably", category: "WebSocket", header: "x-ably-request-id", pattern: "", version_prefix: "" },

    // -- WebRTC --
    HeaderSig { name: "LiveKit", category: "WebRTC", header: "server", pattern: "livekit", version_prefix: "" },
    HeaderSig { name: "Jitsi", category: "WebRTC", header: "server", pattern: "jitsi", version_prefix: "" },
    HeaderSig { name: "BigBlueButton", category: "WebRTC", header: "server", pattern: "bigbluebutton", version_prefix: "" },
    HeaderSig { name: "Agora", category: "WebRTC", header: "x-agora-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Twilio Video", category: "WebRTC", header: "x-twilio-video-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Daily.co", category: "WebRTC", header: "x-daily-request-id", pattern: "", version_prefix: "" },

    // -- API Gateway --
    HeaderSig { name: "Apache APISIX Dashboard", category: "API Gateway", header: "x-apisix-dashboard", pattern: "", version_prefix: "" },
    HeaderSig { name: "Gravitee APIM", category: "API Gateway", header: "x-gravitee-api", pattern: "", version_prefix: "" },

    // -- GraphQL --
    HeaderSig { name: "AWS AppSync", category: "GraphQL", header: "x-amzn-appsync-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Hasura Cloud", category: "GraphQL", header: "x-hasura-cloud-request-id", pattern: "", version_prefix: "" },
    HeaderSig { name: "Stellate", category: "GraphQL", header: "x-stellate-cache", pattern: "", version_prefix: "" },
    HeaderSig { name: "GraphQL Mesh", category: "GraphQL", header: "x-graphql-mesh", pattern: "", version_prefix: "" },
    HeaderSig { name: "WunderGraph", category: "GraphQL", header: "x-wundergraph-request-id", pattern: "", version_prefix: "" },
];

/// Total number of Wappalyzer header signatures.
pub const SIGNATURE_COUNT: usize = SIGNATURES.len();

// ─── Detection engine ────────────────────────────────────────────────────────

/// Detect technologies from HTTP headers using the Wappalyzer signature database.
/// Returns all matching technologies (there can be multiple: e.g., Nginx + PHP + WordPress).
pub fn detect_from_headers(
    headers: &[(String, String)],
    server_header: Option<&str>,
    powered_by: Option<&str>,
) -> Vec<DetectedTech> {
    let mut results: Vec<DetectedTech> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Build lowercase header map for efficient lookup
    let header_map: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    // Also include Server and X-Powered-By if provided separately
    let server_lower = server_header.map(|s| s.to_lowercase());
    let powered_lower = powered_by.map(|s| s.to_lowercase());

    for sig in SIGNATURES {
        // Check if this signature matches
        let matched = match sig.header {
            "server" => {
                if let Some(ref sv) = server_lower {
                    if sig.pattern.is_empty() {
                        true
                    } else {
                        sv.contains(sig.pattern)
                    }
                } else {
                    check_header_map(&header_map, "server", sig.pattern)
                }
            }
            "x-powered-by" => {
                if let Some(ref pb) = powered_lower {
                    if sig.pattern.is_empty() {
                        true
                    } else {
                        pb.contains(sig.pattern)
                    }
                } else {
                    check_header_map(&header_map, "x-powered-by", sig.pattern)
                }
            }
            _ => check_header_map(&header_map, sig.header, sig.pattern),
        };

        if !matched {
            continue;
        }

        // Deduplicate by name
        let key = sig.name;
        if seen.contains(key) {
            continue;
        }
        seen.insert(key);

        // Try to extract version
        let version = if !sig.version_prefix.is_empty() {
            let source = match sig.header {
                "server" => server_header.unwrap_or(""),
                "x-powered-by" => powered_by.unwrap_or(""),
                _ => {
                    // Find the original header value
                    headers
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == sig.header)
                        .map(|(_, v)| v.as_str())
                        .unwrap_or("")
                }
            };
            extract_header_version(source, sig.version_prefix)
        } else {
            String::new()
        };

        results.push(DetectedTech {
            name: sig.name.to_string(),
            category: sig.category.to_string(),
            version,
        });
    }

    results
}

/// Check if a header exists in the map and optionally matches a pattern.
fn check_header_map(headers: &[(String, String)], header_name: &str, pattern: &str) -> bool {
    for (k, v) in headers {
        if k == header_name {
            if pattern.is_empty() {
                return true; // Header existence is enough
            }
            if v.contains(pattern) {
                return true;
            }
        }
    }
    false
}

/// Extract version from a header value using "prefix/version" pattern.
fn extract_header_version(header_value: &str, prefix: &str) -> String {
    let lower = header_value.to_lowercase();
    let prefix_lower = prefix.to_lowercase();

    if let Some(idx) = lower.find(&prefix_lower) {
        let after = &header_value[idx + prefix.len()..];
        if let Some(rest) = after.strip_prefix('/') {
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                .collect();
            if !version.is_empty() {
                return version;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx() {
        let result = detect_from_headers(&[], Some("nginx/1.24.0"), None);
        assert!(result.iter().any(|t| t.name == "Nginx"));
        let nginx = result.iter().find(|t| t.name == "Nginx").unwrap();
        assert_eq!(nginx.version, "1.24.0");
    }

    #[test]
    fn test_detect_php_powered_by() {
        let result = detect_from_headers(&[], None, Some("PHP/8.2.1"));
        assert!(result.iter().any(|t| t.name == "PHP"));
        let php = result.iter().find(|t| t.name == "PHP").unwrap();
        assert_eq!(php.version, "8.2.1");
    }

    #[test]
    fn test_detect_multiple_technologies() {
        let headers = vec![
            ("x-varnish".to_string(), "12345".to_string()),
            ("x-drupal-cache".to_string(), "HIT".to_string()),
        ];
        let result = detect_from_headers(&headers, Some("Apache/2.4.52"), Some("PHP/8.1"));
        assert!(result.iter().any(|t| t.name == "Apache HTTP Server"));
        assert!(result.iter().any(|t| t.name == "PHP"));
        assert!(result.iter().any(|t| t.name == "Varnish"));
        assert!(result.iter().any(|t| t.name == "Drupal"));
    }

    #[test]
    fn test_detect_cloudflare() {
        let headers = vec![("cf-ray".to_string(), "abc123".to_string())];
        let result = detect_from_headers(&headers, Some("cloudflare"), None);
        assert!(result.iter().any(|t| t.name == "Cloudflare"));
    }

    #[test]
    fn test_signature_count() {
        assert!(SIGNATURE_COUNT > 1500, "Expected 1500+ signatures, got {}", SIGNATURE_COUNT);
    }

    #[test]
    fn test_version_extraction() {
        assert_eq!(extract_header_version("nginx/1.24.0", "nginx"), "1.24.0");
        assert_eq!(extract_header_version("Apache/2.4.52 (Ubuntu)", "apache"), "2.4.52");
        assert_eq!(extract_header_version("no version here", "nginx"), "");
    }
}
