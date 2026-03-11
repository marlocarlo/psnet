//! Comprehensive technology fingerprint database for server detection.
//! Inspired by Wappalyzer's technology database with patterns for
//! process names, command lines, HTTP headers, banners, and ports.

use super::types::ServerKind;

/// A single technology fingerprint with detection patterns across multiple signals.
pub struct TechFingerprint {
    /// Which ServerKind this fingerprint identifies.
    pub kind: ServerKind,
    /// Priority (lower = checked first, matched first). For overlapping patterns.
    pub priority: u8,
    // ── Process-level detection ──
    /// Exact process name stems (lowercase, without .exe). Any match triggers.
    pub process_names: &'static [&'static str],
    /// Substrings to look for in the exe path (lowercase). Any match triggers.
    pub exe_path_contains: &'static [&'static str],
    /// Substrings to look for in the command line (lowercase). All must be present with process.
    pub cmdline_contains: &'static [&'static str],
    /// Only check cmdline if process name stem matches one of these (lowercase). Empty = any process.
    pub cmdline_requires_process: &'static [&'static str],
    // ── HTTP detection ──
    /// Substrings in the Server header (lowercase). Any match triggers.
    pub http_server_contains: &'static [&'static str],
    /// Substrings in X-Powered-By header (lowercase). Any match triggers.
    pub http_powered_by_contains: &'static [&'static str],
    /// (header_name_lowercase, value_substring_lowercase) pairs. Any match triggers.
    pub http_header_contains: &'static [(&'static str, &'static str)],
    /// Substrings in HTML <title> (lowercase). Any match triggers.
    pub html_title_contains: &'static [&'static str],
    // ── Banner detection ──
    /// Banner must start with one of these. Any match triggers.
    pub banner_starts_with: &'static [&'static str],
    /// Substrings in banner text (lowercase). Any match triggers.
    pub banner_contains: &'static [&'static str],
    // ── Port fallback ──
    /// Default ports for this technology. Used as last-resort detection.
    pub default_ports: &'static [u16],
    // ── Version extraction ──
    /// Prefix for extracting version from Server header (e.g., "nginx" extracts from "nginx/1.24").
    pub version_from_header_prefix: Option<&'static str>,
}

/// Master fingerprint database. Ordered by priority (lower = checked first).
pub static FINGERPRINTS: &[TechFingerprint] = &[
    // ═══════════════════════════════════════════════════════════════════════════
    // WEB SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Nginx ──
    TechFingerprint {
        kind: ServerKind::Nginx,
        priority: 10,
        process_names: &["nginx"],
        exe_path_contains: &["nginx"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["nginx", "openresty", "angie"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["welcome to nginx"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8080],
        version_from_header_prefix: Some("nginx"),
    },

    // ── Apache HTTP Server ──
    TechFingerprint {
        kind: ServerKind::Apache,
        priority: 10,
        process_names: &["httpd", "apache2", "apache"],
        exe_path_contains: &["apache2", "httpd", "xampp"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["apache", "mod_ssl", "mod_perl", "mod_python", "mod_fastcgi", "mod_dav"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["apache2 debian", "apache2 ubuntu", "it works!"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8080, 8443],
        version_from_header_prefix: Some("apache"),
    },

    // ── IIS ──
    TechFingerprint {
        kind: ServerKind::IIS,
        priority: 10,
        process_names: &["w3wp", "iisexpress"],
        exe_path_contains: &["iis", "w3wp"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["microsoft-iis", "microsoft-httpapi"],
        http_powered_by_contains: &["asp.net"],
        http_header_contains: &[("x-aspnet-version", ""), ("x-powered-by", "asp.net")],
        html_title_contains: &["iis windows"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8080],
        version_from_header_prefix: Some("microsoft-iis"),
    },

    // ── Caddy ──
    TechFingerprint {
        kind: ServerKind::Caddy,
        priority: 10,
        process_names: &["caddy"],
        exe_path_contains: &["caddy"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["caddy"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["caddy"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 2015],
        version_from_header_prefix: Some("caddy"),
    },

    // ── LiteSpeed ──
    TechFingerprint {
        kind: ServerKind::LiteSpeed,
        priority: 10,
        process_names: &["litespeed", "lshttpd", "openlitespeed"],
        exe_path_contains: &["litespeed", "lshttpd"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["litespeed"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["litespeed"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8088],
        version_from_header_prefix: Some("litespeed"),
    },

    // ── Traefik ──
    TechFingerprint {
        kind: ServerKind::Traefik,
        priority: 10,
        process_names: &["traefik"],
        exe_path_contains: &["traefik"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["traefik"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["traefik"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8080, 8443],
        version_from_header_prefix: Some("traefik"),
    },

    // ── HAProxy ──
    TechFingerprint {
        kind: ServerKind::HAProxy,
        priority: 10,
        process_names: &["haproxy"],
        exe_path_contains: &["haproxy"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["haproxy"],
        http_powered_by_contains: &[],
        http_header_contains: &[("via", "haproxy"), ("x-haproxy-server-state", "")],
        html_title_contains: &["haproxy statistics", "haproxy stats"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443, 8404, 1936],
        version_from_header_prefix: Some("haproxy"),
    },

    // ── Varnish ──
    TechFingerprint {
        kind: ServerKind::Varnish,
        priority: 10,
        process_names: &["varnishd"],
        exe_path_contains: &["varnish"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["varnish"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-varnish", ""), ("via", "varnish")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 6081, 6082],
        version_from_header_prefix: Some("varnish"),
    },

    // ── Jetty ──
    TechFingerprint {
        kind: ServerKind::Jetty,
        priority: 10,
        process_names: &[],
        exe_path_contains: &["jetty"],
        cmdline_contains: &["jetty"],
        cmdline_requires_process: &["java"],
        http_server_contains: &["jetty"],
        http_powered_by_contains: &["jetty"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 8443],
        version_from_header_prefix: Some("jetty"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (JS / Node.js)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Express.js ──
    TechFingerprint {
        kind: ServerKind::Express,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["express"],
        cmdline_requires_process: &["node", "bun"],
        http_server_contains: &["express"],
        http_powered_by_contains: &["express"],
        http_header_contains: &[("x-powered-by", "express")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000, 4000, 5000],
        version_from_header_prefix: None,
    },

    // ── Fastify ──
    TechFingerprint {
        kind: ServerKind::Fastify,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["fastify"],
        cmdline_requires_process: &["node", "bun"],
        http_server_contains: &["fastify"],
        http_powered_by_contains: &["fastify"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Koa ──
    TechFingerprint {
        kind: ServerKind::Koa,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["koa"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["koa"],
        http_powered_by_contains: &["koa"],
        http_header_contains: &[("x-powered-by", "koa")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── NestJS ──
    TechFingerprint {
        kind: ServerKind::NestJS,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["nest"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["nestjs"],
        http_powered_by_contains: &["nestjs", "express"],
        http_header_contains: &[("x-powered-by", "nest")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Hapi ──
    TechFingerprint {
        kind: ServerKind::Hapi,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["hapi"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["hapi"],
        http_powered_by_contains: &["hapi"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── AdonisJS ──
    TechFingerprint {
        kind: ServerKind::AdonisJS,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["adonis", "adonisjs"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &["adonisjs"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3333],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (Python)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Django ──
    TechFingerprint {
        kind: ServerKind::Django,
        priority: 15,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["django", "manage.py runserver"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["wsgiserver", "django"],
        http_powered_by_contains: &["django"],
        http_header_contains: &[("x-frame-options", "deny"), ("x-powered-by", "django")],
        html_title_contains: &["django", "the install worked"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Flask ──
    TechFingerprint {
        kind: ServerKind::Flask,
        priority: 15,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["flask"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["werkzeug"],
        http_powered_by_contains: &["flask"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5000],
        version_from_header_prefix: Some("werkzeug"),
    },

    // ── FastAPI ──
    TechFingerprint {
        kind: ServerKind::FastAPI,
        priority: 15,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["fastapi", "uvicorn"],
        cmdline_requires_process: &["python", "python3", "uvicorn"],
        http_server_contains: &["uvicorn"],
        http_powered_by_contains: &["fastapi"],
        http_header_contains: &[],
        html_title_contains: &["fastapi"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Tornado ──
    TechFingerprint {
        kind: ServerKind::Tornado,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["tornado"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["tornadoserver", "tornado"],
        http_powered_by_contains: &["tornado"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8888],
        version_from_header_prefix: Some("tornadoserver"),
    },

    // ── Sanic ──
    TechFingerprint {
        kind: ServerKind::Sanic,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["sanic"],
        cmdline_requires_process: &["python", "python3", "sanic"],
        http_server_contains: &["sanic"],
        http_powered_by_contains: &["sanic"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Starlette ──
    TechFingerprint {
        kind: ServerKind::Starlette,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["starlette"],
        cmdline_requires_process: &["python", "python3", "uvicorn"],
        http_server_contains: &["uvicorn"],
        http_powered_by_contains: &["starlette"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Bottle ──
    TechFingerprint {
        kind: ServerKind::Bottle,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["bottle"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["wsgiref", "bottle"],
        http_powered_by_contains: &["bottle"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── CherryPy ──
    TechFingerprint {
        kind: ServerKind::CherryPy,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["cherrypy"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["cherrypy"],
        http_powered_by_contains: &["cherrypy"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: Some("cherrypy"),
    },

    // ── Uvicorn (standalone) ──
    TechFingerprint {
        kind: ServerKind::Uvicorn,
        priority: 25,
        process_names: &["uvicorn"],
        exe_path_contains: &["uvicorn"],
        cmdline_contains: &["uvicorn"],
        cmdline_requires_process: &["python", "python3", "uvicorn"],
        http_server_contains: &["uvicorn"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: Some("uvicorn"),
    },

    // ── Gunicorn ──
    TechFingerprint {
        kind: ServerKind::Gunicorn,
        priority: 25,
        process_names: &["gunicorn"],
        exe_path_contains: &["gunicorn"],
        cmdline_contains: &["gunicorn"],
        cmdline_requires_process: &["python", "python3", "gunicorn"],
        http_server_contains: &["gunicorn"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: Some("gunicorn"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (PHP)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Laravel ──
    TechFingerprint {
        kind: ServerKind::Laravel,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["laravel"],
        cmdline_contains: &["artisan serve", "laravel"],
        cmdline_requires_process: &["php"],
        http_server_contains: &[],
        http_powered_by_contains: &["laravel"],
        http_header_contains: &[("set-cookie", "laravel_session"), ("x-powered-by", "laravel")],
        html_title_contains: &["laravel"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Symfony ──
    TechFingerprint {
        kind: ServerKind::Symfony,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["symfony"],
        cmdline_contains: &["symfony"],
        cmdline_requires_process: &["php"],
        http_server_contains: &[],
        http_powered_by_contains: &["symfony"],
        http_header_contains: &[("x-debug-token", ""), ("x-powered-by", "symfony")],
        html_title_contains: &["symfony"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── WordPress ──
    TechFingerprint {
        kind: ServerKind::WordPress,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["wordpress"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &["wordpress"],
        http_header_contains: &[("x-powered-by", "wordpress"), ("link", "wp-json"), ("x-generator", "wordpress")],
        html_title_contains: &["wordpress"],
        banner_starts_with: &[],
        banner_contains: &["wp-content", "wp-login", "wp-includes"],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Drupal ──
    TechFingerprint {
        kind: ServerKind::Drupal,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["drupal"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &["drupal"],
        http_header_contains: &[("x-drupal-cache", ""), ("x-generator", "drupal")],
        html_title_contains: &["drupal"],
        banner_starts_with: &[],
        banner_contains: &["drupal"],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── PHP Built-in Server ──
    TechFingerprint {
        kind: ServerKind::PhpBuiltIn,
        priority: 30,
        process_names: &["php", "php-cgi"],
        exe_path_contains: &["php"],
        cmdline_contains: &["-s localhost", "-s 0.0.0.0", "-s 127.0.0.1"],
        cmdline_requires_process: &["php"],
        http_server_contains: &["php"],
        http_powered_by_contains: &["php"],
        http_header_contains: &[("x-powered-by", "php")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: Some("php"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (Ruby)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Ruby on Rails ──
    TechFingerprint {
        kind: ServerKind::Rails,
        priority: 15,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["rails server", "rails s", "puma", "bin/rails"],
        cmdline_requires_process: &["ruby", "puma"],
        http_server_contains: &["puma"],
        http_powered_by_contains: &["rails", "phusion passenger"],
        http_header_contains: &[("x-runtime", ""), ("x-request-id", ""), ("x-powered-by", "rails")],
        html_title_contains: &["ruby on rails"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Ruby (generic WEBrick/Puma) ──
    TechFingerprint {
        kind: ServerKind::Ruby,
        priority: 30,
        process_names: &["ruby", "puma"],
        exe_path_contains: &["ruby"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["webrick", "puma", "thin", "unicorn"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000, 9292],
        version_from_header_prefix: Some("webrick"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (Java / JVM)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Spring Boot ──
    TechFingerprint {
        kind: ServerKind::JavaSpringBoot,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["spring-boot", "spring"],
        cmdline_contains: &["spring-boot", "org.springframework"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &["spring", "spring-boot"],
        http_header_contains: &[("x-powered-by", "spring")],
        html_title_contains: &["spring", "whitelabel error page"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Apache Tomcat ──
    TechFingerprint {
        kind: ServerKind::JavaTomcat,
        priority: 15,
        process_names: &["catalina", "tomcat"],
        exe_path_contains: &["tomcat", "catalina"],
        cmdline_contains: &["catalina", "tomcat", "org.apache.catalina"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["apache-coyote", "tomcat", "coyote"],
        http_powered_by_contains: &["servlet", "jsp"],
        http_header_contains: &[("x-powered-by", "servlet"), ("x-powered-by", "jsp")],
        html_title_contains: &["apache tomcat"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 8443, 8005, 8009],
        version_from_header_prefix: Some("apache-coyote"),
    },

    // ── WildFly ──
    TechFingerprint {
        kind: ServerKind::WildFly,
        priority: 15,
        process_names: &["wildfly", "jboss"],
        exe_path_contains: &["wildfly", "jboss"],
        cmdline_contains: &["wildfly", "jboss", "org.jboss"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["wildfly", "jboss"],
        http_powered_by_contains: &["undertow", "wildfly"],
        http_header_contains: &[("x-powered-by", "jboss")],
        html_title_contains: &["wildfly", "jboss"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 9990, 8443],
        version_from_header_prefix: None,
    },

    // ── Micronaut ──
    TechFingerprint {
        kind: ServerKind::Micronaut,
        priority: 20,
        process_names: &[],
        exe_path_contains: &["micronaut"],
        cmdline_contains: &["micronaut", "io.micronaut"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["micronaut"],
        http_powered_by_contains: &["micronaut"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Quarkus ──
    TechFingerprint {
        kind: ServerKind::Quarkus,
        priority: 20,
        process_names: &[],
        exe_path_contains: &["quarkus"],
        cmdline_contains: &["quarkus", "io.quarkus"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["quarkus"],
        http_powered_by_contains: &["quarkus"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (Go)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Gin ──
    TechFingerprint {
        kind: ServerKind::Gin,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["gin"],
        cmdline_requires_process: &[],
        http_server_contains: &["gin"],
        http_powered_by_contains: &["gin"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Echo ──
    TechFingerprint {
        kind: ServerKind::Echo,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["echo"],
        http_powered_by_contains: &["echo"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1323],
        version_from_header_prefix: None,
    },

    // ── Fiber ──
    TechFingerprint {
        kind: ServerKind::Fiber,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["fiber"],
        http_powered_by_contains: &["fiber"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB FRAMEWORKS (CMS / Headless)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Ghost ──
    TechFingerprint {
        kind: ServerKind::Ghost,
        priority: 15,
        process_names: &["ghost"],
        exe_path_contains: &["ghost"],
        cmdline_contains: &["ghost"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &["ghost"],
        http_header_contains: &[("x-powered-by", "ghost")],
        html_title_contains: &["ghost"],
        banner_starts_with: &[],
        banner_contains: &["ghost"],
        default_ports: &[2368],
        version_from_header_prefix: None,
    },

    // ── Strapi ──
    TechFingerprint {
        kind: ServerKind::Strapi,
        priority: 15,
        process_names: &[],
        exe_path_contains: &["strapi"],
        cmdline_contains: &["strapi"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &["strapi"],
        http_header_contains: &[("x-powered-by", "strapi")],
        html_title_contains: &["strapi"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1337],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // APPLICATION RUNTIMES (generic)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Node.js (generic) ──
    TechFingerprint {
        kind: ServerKind::NodeJs,
        priority: 40,
        process_names: &["node", "nodejs"],
        exe_path_contains: &["node", "nodejs", "nvm"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["node"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000, 5000, 8080],
        version_from_header_prefix: None,
    },

    // ── Deno ──
    TechFingerprint {
        kind: ServerKind::Deno,
        priority: 30,
        process_names: &["deno"],
        exe_path_contains: &["deno"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["deno"],
        http_powered_by_contains: &["deno"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Bun ──
    TechFingerprint {
        kind: ServerKind::Bun,
        priority: 30,
        process_names: &["bun"],
        exe_path_contains: &["bun"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["bun"],
        http_powered_by_contains: &["bun"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Python HTTP (generic) ──
    TechFingerprint {
        kind: ServerKind::Python,
        priority: 40,
        process_names: &["python", "python3", "python3.11", "python3.12", "python3.13"],
        exe_path_contains: &["python"],
        cmdline_contains: &["http.server"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["simplehttpserver", "basehttpserver", "python"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["directory listing"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000, 8080],
        version_from_header_prefix: Some("python"),
    },

    // ── .NET Kestrel ──
    TechFingerprint {
        kind: ServerKind::DotNetKestrel,
        priority: 20,
        process_names: &["dotnet"],
        exe_path_contains: &["dotnet"],
        cmdline_contains: &["dotnet"],
        cmdline_requires_process: &[],
        http_server_contains: &["kestrel", "microsoft-kestrel"],
        http_powered_by_contains: &["asp.net"],
        http_header_contains: &[("x-aspnet-version", ""), ("x-powered-by", "asp.net core")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5000, 5001, 5272],
        version_from_header_prefix: Some("kestrel"),
    },

    // ── Go net/http ──
    TechFingerprint {
        kind: ServerKind::GoHttp,
        priority: 40,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["go", "golang"],
        http_powered_by_contains: &["go"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Rust Actix ──
    TechFingerprint {
        kind: ServerKind::RustActix,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["actix-web", "actix"],
        http_powered_by_contains: &["actix"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Rust Axum ──
    TechFingerprint {
        kind: ServerKind::RustAxum,
        priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["axum"],
        http_powered_by_contains: &["axum"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DATABASES
    // ═══════════════════════════════════════════════════════════════════════════

    // ── PostgreSQL ──
    TechFingerprint {
        kind: ServerKind::PostgreSQL,
        priority: 10,
        process_names: &["postgres", "postgresql", "pg_ctl", "postmaster"],
        exe_path_contains: &["postgres", "postgresql", "pgsql"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["postgresql", "postgres"],
        default_ports: &[5432],
        version_from_header_prefix: None,
    },

    // ── MySQL ──
    TechFingerprint {
        kind: ServerKind::MySQL,
        priority: 10,
        process_names: &["mysqld", "mysql"],
        exe_path_contains: &["mysql"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["mysql"],
        default_ports: &[3306],
        version_from_header_prefix: None,
    },

    // ── MariaDB ──
    TechFingerprint {
        kind: ServerKind::MariaDB,
        priority: 9,
        process_names: &["mariadbd", "mariadb"],
        exe_path_contains: &["mariadb"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["mariadb"],
        default_ports: &[3306],
        version_from_header_prefix: None,
    },

    // ── MongoDB ──
    TechFingerprint {
        kind: ServerKind::MongoDB,
        priority: 10,
        process_names: &["mongod", "mongos"],
        exe_path_contains: &["mongodb", "mongod"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["mongodb", "mongod"],
        default_ports: &[27017, 27018, 27019],
        version_from_header_prefix: None,
    },

    // ── Redis ──
    TechFingerprint {
        kind: ServerKind::Redis,
        priority: 10,
        process_names: &["redis-server", "redis"],
        exe_path_contains: &["redis"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["redis", "+pong"],
        default_ports: &[6379, 6380],
        version_from_header_prefix: None,
    },

    // ── SQLite (web interface) ──
    TechFingerprint {
        kind: ServerKind::SQLite,
        priority: 30,
        process_names: &["sqlite3", "sqlite"],
        exe_path_contains: &["sqlite"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["sqlite"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Memcached ──
    TechFingerprint {
        kind: ServerKind::Memcached,
        priority: 10,
        process_names: &["memcached"],
        exe_path_contains: &["memcached"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["memcached"],
        default_ports: &[11211],
        version_from_header_prefix: None,
    },

    // ── Elasticsearch ──
    TechFingerprint {
        kind: ServerKind::Elasticsearch,
        priority: 10,
        process_names: &["elasticsearch"],
        exe_path_contains: &["elasticsearch"],
        cmdline_contains: &["elasticsearch", "org.elasticsearch"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["elasticsearch"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-elastic-product", "elasticsearch")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["cluster_name", "elasticsearch", "you know, for search"],
        default_ports: &[9200, 9300],
        version_from_header_prefix: None,
    },

    // ── ClickHouse ──
    TechFingerprint {
        kind: ServerKind::ClickHouse,
        priority: 10,
        process_names: &["clickhouse-server", "clickhouse"],
        exe_path_contains: &["clickhouse"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["clickhouse"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["clickhouse"],
        banner_starts_with: &[],
        banner_contains: &["clickhouse"],
        default_ports: &[8123, 9000, 9440],
        version_from_header_prefix: None,
    },

    // ── CockroachDB ──
    TechFingerprint {
        kind: ServerKind::CockroachDB,
        priority: 10,
        process_names: &["cockroach"],
        exe_path_contains: &["cockroach"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["cockroachdb"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["cockroachdb"],
        banner_starts_with: &[],
        banner_contains: &["cockroachdb"],
        default_ports: &[26257, 8080],
        version_from_header_prefix: None,
    },

    // ── Microsoft SQL Server ──
    TechFingerprint {
        kind: ServerKind::MSSQL,
        priority: 10,
        process_names: &["sqlservr", "sqlserver"],
        exe_path_contains: &["mssql", "sqlserver", "microsoft sql server"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["sqlserver", "mssql"],
        default_ports: &[1433, 1434],
        version_from_header_prefix: None,
    },

    // ── CouchDB ──
    TechFingerprint {
        kind: ServerKind::CouchDB,
        priority: 10,
        process_names: &["couchdb", "beam.smp"],
        exe_path_contains: &["couchdb"],
        cmdline_contains: &["couchdb"],
        cmdline_requires_process: &[],
        http_server_contains: &["couchdb"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["couchdb", "welcome"],
        default_ports: &[5984],
        version_from_header_prefix: Some("couchdb"),
    },

    // ── Neo4j ──
    TechFingerprint {
        kind: ServerKind::Neo4j,
        priority: 10,
        process_names: &["neo4j"],
        exe_path_contains: &["neo4j"],
        cmdline_contains: &["neo4j", "org.neo4j"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["neo4j"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["neo4j browser"],
        banner_starts_with: &[],
        banner_contains: &["neo4j"],
        default_ports: &[7474, 7687],
        version_from_header_prefix: None,
    },

    // ── InfluxDB ──
    TechFingerprint {
        kind: ServerKind::InfluxDB,
        priority: 10,
        process_names: &["influxd", "influxdb"],
        exe_path_contains: &["influxdb", "influxd"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["influxdb"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-influxdb-version", ""), ("x-influxdb-build", "")],
        html_title_contains: &["influxdb"],
        banner_starts_with: &[],
        banner_contains: &["influxdb"],
        default_ports: &[8086],
        version_from_header_prefix: None,
    },

    // ── Cassandra ──
    TechFingerprint {
        kind: ServerKind::Cassandra,
        priority: 10,
        process_names: &["cassandra"],
        exe_path_contains: &["cassandra"],
        cmdline_contains: &["cassandra", "org.apache.cassandra"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["cassandra"],
        default_ports: &[9042, 7000, 7001],
        version_from_header_prefix: None,
    },

    // ── Apache Solr ──
    TechFingerprint {
        kind: ServerKind::Solr,
        priority: 10,
        process_names: &["solr"],
        exe_path_contains: &["solr"],
        cmdline_contains: &["solr", "org.apache.solr"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["solr"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["solr admin"],
        banner_starts_with: &[],
        banner_contains: &["solr"],
        default_ports: &[8983],
        version_from_header_prefix: None,
    },

    // ── Meilisearch ──
    TechFingerprint {
        kind: ServerKind::MeiliSearch,
        priority: 10,
        process_names: &["meilisearch"],
        exe_path_contains: &["meilisearch"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["meilisearch"],
        http_powered_by_contains: &["meilisearch"],
        http_header_contains: &[],
        html_title_contains: &["meilisearch"],
        banner_starts_with: &[],
        banner_contains: &["meilisearch"],
        default_ports: &[7700],
        version_from_header_prefix: None,
    },

    // ── Typesense ──
    TechFingerprint {
        kind: ServerKind::Typesense,
        priority: 10,
        process_names: &["typesense-server", "typesense"],
        exe_path_contains: &["typesense"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["typesense"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["typesense"],
        default_ports: &[8108],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MESSAGE BROKERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── RabbitMQ ──
    TechFingerprint {
        kind: ServerKind::RabbitMQ,
        priority: 10,
        process_names: &["rabbitmq-server", "beam.smp", "rabbitmq"],
        exe_path_contains: &["rabbitmq"],
        cmdline_contains: &["rabbitmq"],
        cmdline_requires_process: &[],
        http_server_contains: &["cowboy"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["rabbitmq management"],
        banner_starts_with: &["AMQP"],
        banner_contains: &["rabbitmq", "amqp"],
        default_ports: &[5672, 15672, 25672],
        version_from_header_prefix: None,
    },

    // ── Apache Kafka ──
    TechFingerprint {
        kind: ServerKind::Kafka,
        priority: 10,
        process_names: &["kafka"],
        exe_path_contains: &["kafka"],
        cmdline_contains: &["kafka.kafka", "kafka-server", "org.apache.kafka"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["kafka"],
        default_ports: &[9092, 9093],
        version_from_header_prefix: None,
    },

    // ── NATS ──
    TechFingerprint {
        kind: ServerKind::NATS,
        priority: 10,
        process_names: &["nats-server", "gnatsd"],
        exe_path_contains: &["nats-server", "gnatsd"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["INFO {"],
        banner_contains: &["nats", "server_id"],
        default_ports: &[4222, 8222, 6222],
        version_from_header_prefix: None,
    },

    // ── Mosquitto (MQTT) ──
    TechFingerprint {
        kind: ServerKind::Mosquitto,
        priority: 10,
        process_names: &["mosquitto"],
        exe_path_contains: &["mosquitto"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["mosquitto", "mqtt"],
        default_ports: &[1883, 8883, 9001],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DEV TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Vite Dev Server ──
    TechFingerprint {
        kind: ServerKind::ViteDevServer,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["vite", "node_modules/.bin/vite", "node_modules/vite"],
        cmdline_requires_process: &["node", "bun"],
        http_server_contains: &["vite"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["vite"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5173, 5174, 3000],
        version_from_header_prefix: None,
    },

    // ── Webpack Dev Server ──
    TechFingerprint {
        kind: ServerKind::WebpackDevServer,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["webpack", "webpack-dev-server", "webpack serve"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["webpack-dev-server"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["webpack"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 9000],
        version_from_header_prefix: None,
    },

    // ── Next.js ──
    TechFingerprint {
        kind: ServerKind::NextJs,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["next dev", "next start", "next-server", "node_modules/next"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["next.js"],
        http_powered_by_contains: &["next.js"],
        http_header_contains: &[("x-powered-by", "next.js"), ("x-nextjs-page", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Nuxt.js ──
    TechFingerprint {
        kind: ServerKind::Nuxt,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["nuxt", "node_modules/nuxt", "nuxi dev"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["nuxt"],
        http_powered_by_contains: &["nuxt"],
        http_header_contains: &[("x-powered-by", "nuxt")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Remix ──
    TechFingerprint {
        kind: ServerKind::Remix,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["remix dev", "node_modules/remix", "@remix-run"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &["remix"],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Create React App ──
    TechFingerprint {
        kind: ServerKind::CreateReactApp,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["react-scripts start", "react-scripts"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["react app"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Angular CLI ──
    TechFingerprint {
        kind: ServerKind::AngularCli,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["ng serve", "@angular/cli", "angular-cli"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["angular"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[4200],
        version_from_header_prefix: None,
    },

    // ── Vue CLI ──
    TechFingerprint {
        kind: ServerKind::VueCli,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["vue-cli-service serve", "@vue/cli-service", "vue-cli"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["vue"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── SvelteKit ──
    TechFingerprint {
        kind: ServerKind::SvelteKit,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["svelte-kit", "sveltekit", "node_modules/@sveltejs"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["sveltekit"],
        http_powered_by_contains: &["sveltekit"],
        http_header_contains: &[],
        html_title_contains: &["sveltekit", "svelte"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5173],
        version_from_header_prefix: None,
    },

    // ── Astro ──
    TechFingerprint {
        kind: ServerKind::Astro,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["astro dev", "node_modules/astro", "astro preview"],
        cmdline_requires_process: &["node"],
        http_server_contains: &["astro"],
        http_powered_by_contains: &["astro"],
        http_header_contains: &[],
        html_title_contains: &["astro"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[4321, 3000],
        version_from_header_prefix: None,
    },

    // ── Hugo ──
    TechFingerprint {
        kind: ServerKind::Hugo,
        priority: 5,
        process_names: &["hugo"],
        exe_path_contains: &["hugo"],
        cmdline_contains: &["hugo server", "hugo serve"],
        cmdline_requires_process: &["hugo"],
        http_server_contains: &["hugo"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1313],
        version_from_header_prefix: None,
    },

    // ── Gatsby ──
    TechFingerprint {
        kind: ServerKind::Gatsby,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["gatsby develop", "gatsby serve", "node_modules/gatsby"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &["gatsby"],
        http_header_contains: &[("x-powered-by", "gatsby")],
        html_title_contains: &["gatsby"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000, 9000],
        version_from_header_prefix: None,
    },

    // ── Storybook ──
    TechFingerprint {
        kind: ServerKind::Storybook,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["storybook", "start-storybook", "node_modules/@storybook"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["storybook"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[6006],
        version_from_header_prefix: None,
    },

    // ── Jupyter Notebook ──
    TechFingerprint {
        kind: ServerKind::Jupyter,
        priority: 5,
        process_names: &["jupyter", "jupyter-notebook", "jupyter-lab"],
        exe_path_contains: &["jupyter"],
        cmdline_contains: &["jupyter", "notebook", "jupyterlab"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["tornado"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["jupyter", "jupyterlab"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8888, 8889],
        version_from_header_prefix: None,
    },

    // ── pgAdmin ──
    TechFingerprint {
        kind: ServerKind::PgAdmin,
        priority: 5,
        process_names: &["pgadmin4", "pgadmin"],
        exe_path_contains: &["pgadmin"],
        cmdline_contains: &["pgadmin"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["pgadmin"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5050],
        version_from_header_prefix: None,
    },

    // ── Swagger UI ──
    TechFingerprint {
        kind: ServerKind::Swagger,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["swagger"],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["swagger ui", "swagger editor", "swagger"],
        banner_starts_with: &[],
        banner_contains: &["swagger"],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // INFRASTRUCTURE
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Docker ──
    TechFingerprint {
        kind: ServerKind::Docker,
        priority: 10,
        process_names: &["dockerd", "docker-proxy", "com.docker.backend"],
        exe_path_contains: &["docker"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["docker"],
        http_powered_by_contains: &[],
        http_header_contains: &[("docker-experimental", ""), ("api-version", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[2375, 2376],
        version_from_header_prefix: None,
    },

    // ── Kubernetes ──
    TechFingerprint {
        kind: ServerKind::Kubernetes,
        priority: 10,
        process_names: &["kube-apiserver", "kubelet", "kube-proxy"],
        exe_path_contains: &["kubernetes", "kube"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["kubernetes"],
        default_ports: &[6443, 8443, 10250],
        version_from_header_prefix: None,
    },

    // ── Prometheus ──
    TechFingerprint {
        kind: ServerKind::Prometheus,
        priority: 10,
        process_names: &["prometheus"],
        exe_path_contains: &["prometheus"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["prometheus time series"],
        banner_starts_with: &[],
        banner_contains: &["prometheus"],
        default_ports: &[9090],
        version_from_header_prefix: None,
    },

    // ── Grafana ──
    TechFingerprint {
        kind: ServerKind::Grafana,
        priority: 10,
        process_names: &["grafana-server", "grafana"],
        exe_path_contains: &["grafana"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["grafana"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["grafana"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Jenkins ──
    TechFingerprint {
        kind: ServerKind::Jenkins,
        priority: 10,
        process_names: &["jenkins"],
        exe_path_contains: &["jenkins"],
        cmdline_contains: &["jenkins", "jenkins.war"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["jetty", "jenkins"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-jenkins", ""), ("x-hudson", "")],
        html_title_contains: &["jenkins", "dashboard [jenkins]"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 50000],
        version_from_header_prefix: None,
    },

    // ── GitLab Runner ──
    TechFingerprint {
        kind: ServerKind::GitLabRunner,
        priority: 10,
        process_names: &["gitlab-runner"],
        exe_path_contains: &["gitlab-runner"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["gitlab"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8093],
        version_from_header_prefix: None,
    },

    // ── Consul ──
    TechFingerprint {
        kind: ServerKind::Consul,
        priority: 10,
        process_names: &["consul"],
        exe_path_contains: &["consul"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["consul"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-consul-index", "")],
        html_title_contains: &["consul"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8500, 8501, 8300, 8301, 8302, 8600],
        version_from_header_prefix: None,
    },

    // ── Vault ──
    TechFingerprint {
        kind: ServerKind::Vault,
        priority: 10,
        process_names: &["vault"],
        exe_path_contains: &["vault"],
        cmdline_contains: &["vault server"],
        cmdline_requires_process: &["vault"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-vault-request", "")],
        html_title_contains: &["vault"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8200],
        version_from_header_prefix: None,
    },

    // ── MinIO ──
    TechFingerprint {
        kind: ServerKind::MinIO,
        priority: 10,
        process_names: &["minio"],
        exe_path_contains: &["minio"],
        cmdline_contains: &["minio server"],
        cmdline_requires_process: &["minio"],
        http_server_contains: &["minio"],
        http_powered_by_contains: &[],
        http_header_contains: &[("server", "minio")],
        html_title_contains: &["minio"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9000, 9001],
        version_from_header_prefix: None,
    },

    // ── Nginx Proxy Manager ──
    TechFingerprint {
        kind: ServerKind::NginxProxyManager,
        priority: 8,
        process_names: &[],
        exe_path_contains: &["nginx-proxy-manager"],
        cmdline_contains: &["nginx-proxy-manager"],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["nginx proxy manager"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[81],
        version_from_header_prefix: None,
    },

    // ── Envoy Proxy ──
    TechFingerprint {
        kind: ServerKind::Envoy,
        priority: 10,
        process_names: &["envoy"],
        exe_path_contains: &["envoy"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["envoy"],
        http_powered_by_contains: &[],
        http_header_contains: &[("server", "envoy"), ("x-envoy-upstream-service-time", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9901, 10000],
        version_from_header_prefix: None,
    },

    // ── Jaeger ──
    TechFingerprint {
        kind: ServerKind::Jaeger,
        priority: 10,
        process_names: &["jaeger", "jaeger-all-in-one", "jaeger-collector", "jaeger-query"],
        exe_path_contains: &["jaeger"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["jaeger ui", "jaeger"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[16686, 14268, 14250, 6831],
        version_from_header_prefix: None,
    },

    // ── Zipkin ──
    TechFingerprint {
        kind: ServerKind::Zipkin,
        priority: 10,
        process_names: &["zipkin"],
        exe_path_contains: &["zipkin"],
        cmdline_contains: &["zipkin"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["zipkin"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9411],
        version_from_header_prefix: None,
    },

    // ── Keycloak ──
    TechFingerprint {
        kind: ServerKind::Keycloak,
        priority: 10,
        process_names: &["keycloak"],
        exe_path_contains: &["keycloak"],
        cmdline_contains: &["keycloak", "org.keycloak"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-powered-by", "keycloak")],
        html_title_contains: &["keycloak"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 8443],
        version_from_header_prefix: None,
    },

    // ── Kong Gateway ──
    TechFingerprint {
        kind: ServerKind::Kong,
        priority: 10,
        process_names: &["kong"],
        exe_path_contains: &["kong"],
        cmdline_contains: &["kong"],
        cmdline_requires_process: &[],
        http_server_contains: &["kong"],
        http_powered_by_contains: &[],
        http_header_contains: &[("via", "kong"), ("server", "kong")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000, 8001, 8443, 8444],
        version_from_header_prefix: Some("kong"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SYSTEM SERVICES
    // ═══════════════════════════════════════════════════════════════════════════

    // ── OpenSSH ──
    TechFingerprint {
        kind: ServerKind::OpenSSH,
        priority: 5,
        process_names: &["sshd"],
        exe_path_contains: &["ssh", "openssh"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["SSH-"],
        banner_contains: &["openssh", "ssh-2.0"],
        default_ports: &[22],
        version_from_header_prefix: None,
    },

    // ── SMB ──
    TechFingerprint {
        kind: ServerKind::SMB,
        priority: 5,
        process_names: &["smbd"],
        exe_path_contains: &["samba"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["smb", "samba"],
        default_ports: &[445, 139],
        version_from_header_prefix: None,
    },

    // ── DNS ──
    TechFingerprint {
        kind: ServerKind::DNS,
        priority: 5,
        process_names: &["named", "bind9", "unbound", "dnsmasq", "coredns"],
        exe_path_contains: &["named", "bind", "unbound", "dnsmasq", "coredns"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[53],
        version_from_header_prefix: None,
    },

    // ── DHCP ──
    TechFingerprint {
        kind: ServerKind::DHCP,
        priority: 5,
        process_names: &["dhcpd", "dhcpcd", "dhcp-server", "isc-dhcp-server"],
        exe_path_contains: &["dhcp"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[67, 68],
        version_from_header_prefix: None,
    },

    // ── FTP ──
    TechFingerprint {
        kind: ServerKind::FTP,
        priority: 5,
        process_names: &["vsftpd", "proftpd", "pure-ftpd", "ftpd"],
        exe_path_contains: &["vsftpd", "proftpd", "pure-ftpd", "filezilla server"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["220 ", "220-"],
        banner_contains: &["ftp", "filezilla", "vsftpd", "proftpd"],
        default_ports: &[21, 990],
        version_from_header_prefix: None,
    },

    // ── SMTP ──
    TechFingerprint {
        kind: ServerKind::SMTP,
        priority: 5,
        process_names: &["smtpd", "master"],
        exe_path_contains: &["postfix", "exim", "sendmail"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["220 "],
        banner_contains: &["smtp", "esmtp", "mail", "postfix", "exim", "sendmail"],
        default_ports: &[25, 465, 587],
        version_from_header_prefix: None,
    },

    // ── Postfix ──
    TechFingerprint {
        kind: ServerKind::Postfix,
        priority: 4,
        process_names: &["master"],
        exe_path_contains: &["postfix"],
        cmdline_contains: &["postfix"],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["postfix"],
        default_ports: &[25, 465, 587],
        version_from_header_prefix: None,
    },

    // ── Dovecot ──
    TechFingerprint {
        kind: ServerKind::Dovecot,
        priority: 4,
        process_names: &["dovecot"],
        exe_path_contains: &["dovecot"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["dovecot", "imap"],
        default_ports: &[143, 993, 110, 995],
        version_from_header_prefix: None,
    },

    // ── RDP ──
    TechFingerprint {
        kind: ServerKind::RDP,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["termservice"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3389],
        version_from_header_prefix: None,
    },

    // ── VNC ──
    TechFingerprint {
        kind: ServerKind::VNC,
        priority: 5,
        process_names: &["vncserver", "x11vnc", "tigervnc", "Xvnc"],
        exe_path_contains: &["vnc", "tigervnc", "tightvnc", "realvnc"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["RFB "],
        banner_contains: &["rfb", "vnc"],
        default_ports: &[5900, 5901, 5902],
        version_from_header_prefix: None,
    },

    // ── WinRM ──
    TechFingerprint {
        kind: ServerKind::WinRM,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["winrm"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &["microsoft-httpapi"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5985, 5986],
        version_from_header_prefix: None,
    },

    // ── Print Spooler ──
    TechFingerprint {
        kind: ServerKind::PrintSpooler,
        priority: 5,
        process_names: &["spoolsv"],
        exe_path_contains: &["spoolsv"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[515, 631, 9100],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MEDIA SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Plex Media Server ──
    TechFingerprint {
        kind: ServerKind::Plex,
        priority: 10,
        process_names: &["plex media server", "plexmediaserver"],
        exe_path_contains: &["plex"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-plex-protocol", "")],
        html_title_contains: &["plex"],
        banner_starts_with: &[],
        banner_contains: &["plex"],
        default_ports: &[32400],
        version_from_header_prefix: None,
    },

    // ── Jellyfin ──
    TechFingerprint {
        kind: ServerKind::Jellyfin,
        priority: 10,
        process_names: &["jellyfin"],
        exe_path_contains: &["jellyfin"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["jellyfin"],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-emby-authorization", "")],
        html_title_contains: &["jellyfin"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8096, 8920],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SECONDARY / ALTERNATIVE DETECTION PATTERNS
    // These provide additional detection vectors for technologies that can
    // be identified through multiple independent signals.
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Nginx (OpenResty variant) ──
    TechFingerprint {
        kind: ServerKind::Nginx,
        priority: 11,
        process_names: &["openresty"],
        exe_path_contains: &["openresty"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["openresty"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["openresty"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: Some("openresty"),
    },

    // ── Nginx (Tengine variant) ──
    TechFingerprint {
        kind: ServerKind::Nginx,
        priority: 11,
        process_names: &["tengine"],
        exe_path_contains: &["tengine"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["tengine"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: Some("tengine"),
    },

    // ── Apache (XAMPP) ──
    TechFingerprint {
        kind: ServerKind::Apache,
        priority: 11,
        process_names: &[],
        exe_path_contains: &["xampp", "wamp", "mamp", "lampp"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["xampp", "wamp", "mamp"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: None,
    },

    // ── IIS (ASP.NET Core) ──
    TechFingerprint {
        kind: ServerKind::IIS,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &["asp.net core"],
        http_header_contains: &[("x-aspnetmvc-version", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Express.js (alternative X-Powered-By) ──
    TechFingerprint {
        kind: ServerKind::Express,
        priority: 21,
        process_names: &[],
        exe_path_contains: &["node_modules/express"],
        cmdline_contains: &["node_modules/express", "ts-node"],
        cmdline_requires_process: &["node", "ts-node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("etag", "w/")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3001, 4000, 5000, 8080],
        version_from_header_prefix: None,
    },

    // ── NestJS (alternative cmdline patterns) ──
    TechFingerprint {
        kind: ServerKind::NestJS,
        priority: 21,
        process_names: &[],
        exe_path_contains: &["node_modules/@nestjs"],
        cmdline_contains: &["@nestjs", "nest start"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Django (alternative: CSRF cookie) ──
    TechFingerprint {
        kind: ServerKind::Django,
        priority: 16,
        process_names: &["manage.py"],
        exe_path_contains: &["django"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("set-cookie", "csrftoken")],
        html_title_contains: &["django administration", "log in | django"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000, 8001],
        version_from_header_prefix: None,
    },

    // ── Flask (alternative: Werkzeug debugger) ──
    TechFingerprint {
        kind: ServerKind::Flask,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["werkzeug debugger"],
        banner_starts_with: &[],
        banner_contains: &["werkzeug"],
        default_ports: &[5000, 5001],
        version_from_header_prefix: None,
    },

    // ── FastAPI (alternative: OpenAPI docs page) ──
    TechFingerprint {
        kind: ServerKind::FastAPI,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["fastapi - swagger ui"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Laravel (alternative: artisan serve) ──
    TechFingerprint {
        kind: ServerKind::Laravel,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["artisan"],
        cmdline_requires_process: &["php"],
        http_server_contains: &["php"],
        http_powered_by_contains: &[],
        http_header_contains: &[("set-cookie", "xsrf-token")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── WordPress (alternative: REST API) ──
    TechFingerprint {
        kind: ServerKind::WordPress,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("link", "rest_route"), ("x-wp-total", "")],
        html_title_contains: &["log in", "wp-admin"],
        banner_starts_with: &[],
        banner_contains: &["wp-json", "xmlrpc.php"],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Spring Boot (alternative: actuator endpoints) ──
    TechFingerprint {
        kind: ServerKind::JavaSpringBoot,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["spring.main", "-jar"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["actuator", "spring"],
        default_ports: &[8080, 8081],
        version_from_header_prefix: None,
    },

    // ── PostgreSQL (alternative: pgbouncer) ──
    TechFingerprint {
        kind: ServerKind::PostgreSQL,
        priority: 11,
        process_names: &["pgbouncer"],
        exe_path_contains: &["pgbouncer"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["pgbouncer"],
        default_ports: &[5432, 6432],
        version_from_header_prefix: None,
    },

    // ── MySQL (alternative: Percona) ──
    TechFingerprint {
        kind: ServerKind::MySQL,
        priority: 11,
        process_names: &["percona-server"],
        exe_path_contains: &["percona"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["percona"],
        default_ports: &[3306],
        version_from_header_prefix: None,
    },

    // ── MongoDB (alternative: mongos router) ──
    TechFingerprint {
        kind: ServerKind::MongoDB,
        priority: 11,
        process_names: &["mongosh"],
        exe_path_contains: &["mongosh"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["ismaster", "iswritableprimary"],
        default_ports: &[27017],
        version_from_header_prefix: None,
    },

    // ── Redis (alternative: KeyDB fork) ──
    TechFingerprint {
        kind: ServerKind::Redis,
        priority: 11,
        process_names: &["keydb-server", "dragonfly"],
        exe_path_contains: &["keydb", "dragonfly"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["keydb", "dragonfly"],
        default_ports: &[6379],
        version_from_header_prefix: None,
    },

    // ── Elasticsearch (alternative: OpenSearch fork) ──
    TechFingerprint {
        kind: ServerKind::Elasticsearch,
        priority: 11,
        process_names: &["opensearch"],
        exe_path_contains: &["opensearch"],
        cmdline_contains: &["opensearch"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["opensearch"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["opensearch"],
        default_ports: &[9200, 9300],
        version_from_header_prefix: None,
    },

    // ── MSSQL (alternative: Azure SQL Edge) ──
    TechFingerprint {
        kind: ServerKind::MSSQL,
        priority: 11,
        process_names: &["sqlserver"],
        exe_path_contains: &["sql server"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["sql server"],
        default_ports: &[1433],
        version_from_header_prefix: None,
    },

    // ── RabbitMQ (alternative: management UI) ──
    TechFingerprint {
        kind: ServerKind::RabbitMQ,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["rabbitmq"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[15672],
        version_from_header_prefix: None,
    },

    // ── Docker (Docker Desktop for Windows) ──
    TechFingerprint {
        kind: ServerKind::Docker,
        priority: 11,
        process_names: &["com.docker.service", "docker desktop"],
        exe_path_contains: &["docker desktop"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[2375, 2376],
        version_from_header_prefix: None,
    },

    // ── Kubernetes (k3s variant) ──
    TechFingerprint {
        kind: ServerKind::Kubernetes,
        priority: 11,
        process_names: &["k3s", "k3s-server", "k3s-agent", "microk8s"],
        exe_path_contains: &["k3s", "microk8s"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[6443],
        version_from_header_prefix: None,
    },

    // ── Grafana (alternative: Loki push) ──
    TechFingerprint {
        kind: ServerKind::Grafana,
        priority: 11,
        process_names: &["grafana"],
        exe_path_contains: &[],
        cmdline_contains: &["grafana-server", "grafana server"],
        cmdline_requires_process: &["grafana"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-grafana-org-id", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Jenkins (alternative: JNLP agent port) ──
    TechFingerprint {
        kind: ServerKind::Jenkins,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-jenkins-session", ""), ("x-ssh-endpoint", "")],
        html_title_contains: &["sign in [jenkins]"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[50000],
        version_from_header_prefix: None,
    },

    // ── OpenSSH (Dropbear variant) ──
    TechFingerprint {
        kind: ServerKind::OpenSSH,
        priority: 6,
        process_names: &["dropbear"],
        exe_path_contains: &["dropbear"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["SSH-2.0-dropbear"],
        banner_contains: &["dropbear"],
        default_ports: &[22],
        version_from_header_prefix: None,
    },

    // ── FTP (FileZilla Server) ──
    TechFingerprint {
        kind: ServerKind::FTP,
        priority: 6,
        process_names: &["filezilla server"],
        exe_path_contains: &["filezilla server"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["filezilla"],
        default_ports: &[21],
        version_from_header_prefix: None,
    },

    // ── SMTP (Exim) ──
    TechFingerprint {
        kind: ServerKind::SMTP,
        priority: 6,
        process_names: &["exim", "exim4"],
        exe_path_contains: &["exim"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["exim"],
        default_ports: &[25, 465, 587],
        version_from_header_prefix: None,
    },

    // ── DNS (Pi-hole) ──
    TechFingerprint {
        kind: ServerKind::DNS,
        priority: 6,
        process_names: &["pihole-ftl"],
        exe_path_contains: &["pihole"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["lighttpd"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["pi-hole"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[53, 80],
        version_from_header_prefix: None,
    },

    // ── Nginx (on Windows path) ──
    TechFingerprint {
        kind: ServerKind::Nginx,
        priority: 12,
        process_names: &[],
        exe_path_contains: &["\\nginx\\", "program files\\nginx"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Apache (on Windows path) ──
    TechFingerprint {
        kind: ServerKind::Apache,
        priority: 12,
        process_names: &[],
        exe_path_contains: &["\\apache24\\", "\\apache2\\", "program files\\apache"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Node.js (via npx/pnpm/yarn) ──
    TechFingerprint {
        kind: ServerKind::NodeJs,
        priority: 41,
        process_names: &[],
        exe_path_contains: &["npx", "pnpm", "yarn"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── .NET Kestrel (via aspnet/blazor) ──
    TechFingerprint {
        kind: ServerKind::DotNetKestrel,
        priority: 21,
        process_names: &[],
        exe_path_contains: &["aspnet", "blazor"],
        cmdline_contains: &["aspnet", "blazor"],
        cmdline_requires_process: &["dotnet"],
        http_server_contains: &[],
        http_powered_by_contains: &["blazor"],
        http_header_contains: &[("blazor-environment", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5000, 5001],
        version_from_header_prefix: None,
    },

    // ── HAProxy (stats/admin page) ──
    TechFingerprint {
        kind: ServerKind::HAProxy,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["statistics report for haproxy", "stats report"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1936, 8404],
        version_from_header_prefix: None,
    },

    // ── Varnish (VCL headers) ──
    TechFingerprint {
        kind: ServerKind::Varnish,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-cache", "hit"), ("x-cache-hits", ""), ("age", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[6081],
        version_from_header_prefix: None,
    },

    // ── Envoy (envoy headers) ──
    TechFingerprint {
        kind: ServerKind::Envoy,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-envoy-decorator-operation", ""), ("x-envoy-attempt-count", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Kong (admin API) ──
    TechFingerprint {
        kind: ServerKind::Kong,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-kong-upstream-latency", ""), ("x-kong-proxy-latency", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8001, 8444],
        version_from_header_prefix: None,
    },

    // ── Consul (DNS interface) ──
    TechFingerprint {
        kind: ServerKind::Consul,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["consul agent"],
        cmdline_requires_process: &["consul"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["consul by hashicorp"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8600],
        version_from_header_prefix: None,
    },

    // ── Plex (alternative: DLNA) ──
    TechFingerprint {
        kind: ServerKind::Plex,
        priority: 11,
        process_names: &["plex media scanner", "plex tuner service"],
        exe_path_contains: &["plex media server"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-plex-content-original-length", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1900, 32469],
        version_from_header_prefix: None,
    },

    // ── Next.js (production server) ──
    TechFingerprint {
        kind: ServerKind::NextJs,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[".next"],
        cmdline_contains: &[".next/standalone"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-nextjs-cache", ""), ("x-nextjs-matched-path", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Nuxt.js (alternative headers) ──
    TechFingerprint {
        kind: ServerKind::Nuxt,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[".nuxt", "node_modules/nuxt3"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-nuxt-no-ssr", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[3000],
        version_from_header_prefix: None,
    },

    // ── Vite Dev Server (alternative patterns) ──
    TechFingerprint {
        kind: ServerKind::ViteDevServer,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["vitest", "vite preview", "vite build"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5173, 4173],
        version_from_header_prefix: None,
    },

    // ── Webpack Dev Server (alternative) ──
    TechFingerprint {
        kind: ServerKind::WebpackDevServer,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["webpack-dev-middleware"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Prometheus (Node Exporter) ──
    TechFingerprint {
        kind: ServerKind::Prometheus,
        priority: 11,
        process_names: &["node_exporter", "windows_exporter", "prometheus-node"],
        exe_path_contains: &["node_exporter", "windows_exporter"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["node exporter", "windows exporter"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9100, 9182],
        version_from_header_prefix: None,
    },

    // ── MinIO (console UI) ──
    TechFingerprint {
        kind: ServerKind::MinIO,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["minio console"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["minio console", "minio browser"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9001],
        version_from_header_prefix: None,
    },

    // ── InfluxDB (Telegraf agent) ──
    TechFingerprint {
        kind: ServerKind::InfluxDB,
        priority: 11,
        process_names: &["telegraf"],
        exe_path_contains: &["telegraf"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8125],
        version_from_header_prefix: None,
    },

    // ── Neo4j (browser UI) ──
    TechFingerprint {
        kind: ServerKind::Neo4j,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["neo4j browser"],
        banner_starts_with: &[],
        banner_contains: &["bolt"],
        default_ports: &[7687],
        version_from_header_prefix: None,
    },

    // ── Keycloak (alternative: OIDC discovery) ──
    TechFingerprint {
        kind: ServerKind::Keycloak,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["keycloak - administration console", "keycloak account"],
        banner_starts_with: &[],
        banner_contains: &["realms", "openid-configuration"],
        default_ports: &[8080, 8443],
        version_from_header_prefix: None,
    },

    // ── Drupal (alternative: generator meta) ──
    TechFingerprint {
        kind: ServerKind::Drupal,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-drupal-dynamic-cache", ""), ("x-drupal-page-cache-debug", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["sites/default", "modules/system"],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Ghost (alternative: members API) ──
    TechFingerprint {
        kind: ServerKind::Ghost,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-ghost-cache-status", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["ghost/api"],
        default_ports: &[2368],
        version_from_header_prefix: None,
    },

    // ── Jupyter (alternative: JupyterHub) ──
    TechFingerprint {
        kind: ServerKind::Jupyter,
        priority: 6,
        process_names: &["jupyterhub", "jupyterhub-singleuser"],
        exe_path_contains: &["jupyterhub"],
        cmdline_contains: &["jupyterhub"],
        cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["jupyterhub"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── CockroachDB (admin UI) ──
    TechFingerprint {
        kind: ServerKind::CockroachDB,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["cockroach start"],
        cmdline_requires_process: &["cockroach"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["cockroachdb console"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080, 26257],
        version_from_header_prefix: None,
    },

    // ── ClickHouse (native protocol) ──
    TechFingerprint {
        kind: ServerKind::ClickHouse,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-clickhouse-server-display-name", "")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9000, 9440],
        version_from_header_prefix: None,
    },

    // ── Solr (admin panel) ──
    TechFingerprint {
        kind: ServerKind::Solr,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["solr admin", "solr administration"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8983],
        version_from_header_prefix: None,
    },

    // ── Kafka (Confluent/Schema Registry) ──
    TechFingerprint {
        kind: ServerKind::Kafka,
        priority: 11,
        process_names: &["schema-registry", "ksqldb-server", "kafka-rest"],
        exe_path_contains: &["confluent"],
        cmdline_contains: &["confluent"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8081, 8082, 8088],
        version_from_header_prefix: None,
    },

    // ── Mosquitto (WebSocket interface) ──
    TechFingerprint {
        kind: ServerKind::Mosquitto,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("upgrade", "websocket")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["mqtt"],
        default_ports: &[9001],
        version_from_header_prefix: None,
    },

    // ── Cassandra (nodetool) ──
    TechFingerprint {
        kind: ServerKind::Cassandra,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["cassandra.yaml"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[7199],
        version_from_header_prefix: None,
    },

    // ── VNC (Windows UltraVNC) ──
    TechFingerprint {
        kind: ServerKind::VNC,
        priority: 6,
        process_names: &["winvnc", "uvnc_service"],
        exe_path_contains: &["ultravnc"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["ultravnc"],
        default_ports: &[5900],
        version_from_header_prefix: None,
    },

    // ── Starlette (alternative: mounting) ──
    TechFingerprint {
        kind: ServerKind::Starlette,
        priority: 21,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["starlette"],
        banner_starts_with: &[],
        banner_contains: &["starlette"],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Swagger (alternative: redoc) ──
    TechFingerprint {
        kind: ServerKind::Swagger,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["redoc", "api documentation", "openapi"],
        banner_starts_with: &[],
        banner_contains: &["openapi", "swagger-ui"],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WildFly (alternative: Undertow standalone) ──
    TechFingerprint {
        kind: ServerKind::WildFly,
        priority: 16,
        process_names: &[],
        exe_path_contains: &["undertow"],
        cmdline_contains: &["undertow"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &["undertow"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["welcome to wildfly"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Jetty (via Eclipse IDE) ──
    TechFingerprint {
        kind: ServerKind::Jetty,
        priority: 11,
        process_names: &[],
        exe_path_contains: &["eclipse"],
        cmdline_contains: &["org.eclipse.jetty"],
        cmdline_requires_process: &["java", "javaw"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── Caddy (file server mode) ──
    TechFingerprint {
        kind: ServerKind::Caddy,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["caddy file-server", "caddy reverse-proxy"],
        cmdline_requires_process: &["caddy"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: None,
    },

    // ── Traefik (dashboard) ──
    TechFingerprint {
        kind: ServerKind::Traefik,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["--api.dashboard"],
        cmdline_requires_process: &["traefik"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["traefik dashboard"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8080],
        version_from_header_prefix: None,
    },

    // ── LiteSpeed (OpenLiteSpeed admin) ──
    TechFingerprint {
        kind: ServerKind::LiteSpeed,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["openlitespeed"],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["openlitespeed"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[7080],
        version_from_header_prefix: Some("openlitespeed"),
    },

    // ── Vault (alternative: seal status) ──
    TechFingerprint {
        kind: ServerKind::Vault,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-vault-cluster-addr", "")],
        html_title_contains: &["vault - hashicorp"],
        banner_starts_with: &[],
        banner_contains: &["vault", "sealed"],
        default_ports: &[8200],
        version_from_header_prefix: None,
    },

    // ── Jaeger (collector gRPC) ──
    TechFingerprint {
        kind: ServerKind::Jaeger,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["opentelemetry"],
        default_ports: &[4317, 4318],
        version_from_header_prefix: None,
    },

    // ── Zipkin (alternative: lens UI) ──
    TechFingerprint {
        kind: ServerKind::Zipkin,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["zipkin - lens"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[9411],
        version_from_header_prefix: None,
    },

    // ── Dovecot (POP3 port) ──
    TechFingerprint {
        kind: ServerKind::Dovecot,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["+OK Dovecot"],
        banner_contains: &[],
        default_ports: &[110, 995],
        version_from_header_prefix: None,
    },

    // ── Postfix (alternative: submission port) ──
    TechFingerprint {
        kind: ServerKind::Postfix,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["220 "],
        banner_contains: &["postfix", "esmtp postfix"],
        default_ports: &[587],
        version_from_header_prefix: None,
    },

    // ── Strapi (admin panel) ──
    TechFingerprint {
        kind: ServerKind::Strapi,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["strapi develop", "strapi start"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["strapi admin"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1337],
        version_from_header_prefix: None,
    },

    // ── Jellyfin (DLNA) ──
    TechFingerprint {
        kind: ServerKind::Jellyfin,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["jellyfin"],
        default_ports: &[1900, 7359],
        version_from_header_prefix: None,
    },

    // ── CouchDB (Fauxton UI) ──
    TechFingerprint {
        kind: ServerKind::CouchDB,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["fauxton", "project fauxton"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5984],
        version_from_header_prefix: None,
    },

    // ── MeiliSearch (dashboard) ──
    TechFingerprint {
        kind: ServerKind::MeiliSearch,
        priority: 11,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["meilisearch mini-dashboard"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[7700],
        version_from_header_prefix: None,
    },

    // ── Nginx Proxy Manager (alternative) ──
    TechFingerprint {
        kind: ServerKind::NginxProxyManager,
        priority: 9,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["login - nginx proxy manager"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[81],
        version_from_header_prefix: None,
    },

    // ── GitLab Runner (alternative: via Docker) ──
    TechFingerprint {
        kind: ServerKind::GitLabRunner,
        priority: 11,
        process_names: &["gitlab-ci-multi-runner"],
        exe_path_contains: &["gitlab-ci"],
        cmdline_contains: &["gitlab-runner run"],
        cmdline_requires_process: &["gitlab-runner"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Symfony (alternative: profiler) ──
    TechFingerprint {
        kind: ServerKind::Symfony,
        priority: 16,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["symfony serve", "bin/console server:start"],
        cmdline_requires_process: &["php", "symfony"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[("x-debug-token-link", "")],
        html_title_contains: &["symfony profiler"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Sanic (alternative: auto-reload) ──
    TechFingerprint {
        kind: ServerKind::Sanic,
        priority: 21,
        process_names: &["sanic"],
        exe_path_contains: &[],
        cmdline_contains: &["sanic server", "--reload"],
        cmdline_requires_process: &["python", "python3", "sanic"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8000],
        version_from_header_prefix: None,
    },

    // ── Tornado (Jupyter backend detection) ──
    TechFingerprint {
        kind: ServerKind::Tornado,
        priority: 21,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &["tornadoserver"],
        http_powered_by_contains: &[],
        http_header_contains: &[("etag", ""), ("content-type", "text/html")],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[8888],
        version_from_header_prefix: None,
    },

    // ── PgAdmin (alternative: login page) ──
    TechFingerprint {
        kind: ServerKind::PgAdmin,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &["pgadmin 4", "pgadmin - login"],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5050, 5051],
        version_from_header_prefix: None,
    },

    // ── Hugo (alternative: livereload) ──
    TechFingerprint {
        kind: ServerKind::Hugo,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["hugo server --watch"],
        cmdline_requires_process: &["hugo"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &["livereload"],
        default_ports: &[1313],
        version_from_header_prefix: None,
    },

    // ── Angular CLI (alternative: ng build --watch) ──
    TechFingerprint {
        kind: ServerKind::AngularCli,
        priority: 6,
        process_names: &[],
        exe_path_contains: &["@angular"],
        cmdline_contains: &["ng build", "ng test"],
        cmdline_requires_process: &["node"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[4200, 9876],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // FALLBACK / GENERIC ENTRIES (low priority)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Custom HTTP (any unrecognized HTTP response) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 90,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &["HTTP/"],
        banner_contains: &[],
        default_ports: &[80, 443, 8080, 8443],
        version_from_header_prefix: None,
    },

    // ── Generic TCP ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 95,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Generic UDP ──
    TechFingerprint {
        kind: ServerKind::GenericUdp,
        priority: 95,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Unknown ──
    TechFingerprint {
        kind: ServerKind::Unknown,
        priority: 99,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // COMMON PROCESSES THAT SHOULD NOT BE MISCLASSIFIED
    // These use CustomHttp/GenericTcp to prevent false positives from port fallback
    // ═══════════════════════════════════════════════════════════════════════════

    // ── VS Code / VS Code Insiders (runs web server for extensions, remote dev) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 5,
        process_names: &["code", "code-insiders", "code-tunnel"],
        exe_path_contains: &["visual studio code", "vscode", "code-insiders"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Electron apps (Slack, Discord, Teams, etc.) — can listen on local ports ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 8,
        process_names: &["electron", "slack", "discord", "teams", "spotify",
                         "signal-desktop", "telegram-desktop", "whatsapp",
                         "obs64", "obs", "postman", "insomnia"],
        exe_path_contains: &["electron"],
        cmdline_contains: &["--type="],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Chrome DevTools / browser debug ports ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 5,
        process_names: &["chrome", "chromium", "msedge", "brave", "vivaldi", "opera"],
        exe_path_contains: &["chrome", "chromium", "edge", "brave", "vivaldi", "opera"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows system processes commonly listening on ports ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 15,
        process_names: &["lsass", "services", "wininit", "csrss", "smss",
                         "dashost", "searchindexer", "searchprotocolhost",
                         "msdtc", "vmms", "vmcompute", "vmwp",
                         "spoolsv", "taskhostw", "sihost"],
        exe_path_contains: &[],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── JetBrains IDEs (IntelliJ, WebStorm, PyCharm, etc.) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 5,
        process_names: &["idea64", "idea", "webstorm64", "webstorm", "pycharm64",
                         "pycharm", "goland64", "goland", "clion64", "clion",
                         "rider64", "rider", "phpstorm64", "phpstorm",
                         "rubymine64", "rubymine", "datagrip64", "datagrip"],
        exe_path_contains: &["jetbrains"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Git / GitHub Desktop ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 12,
        process_names: &["git", "git-remote-https", "git-credential-manager",
                         "github desktop", "gitkraken"],
        exe_path_contains: &["git"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WireGuard / VPN ──
    TechFingerprint {
        kind: ServerKind::GenericUdp,
        priority: 12,
        process_names: &["wireguard", "openvpn", "openvpn-gui"],
        exe_path_contains: &["wireguard", "openvpn"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[51820],
        version_from_header_prefix: None,
    },

    // ── Antivirus / Security suites that listen on local ports ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 15,
        process_names: &["msmpeng", "nissrv", "mssense", "securityhealthservice",
                         "avgnt", "avguard", "avp", "kavtray",
                         "norton", "ccsvchst", "rtvscan",
                         "mbam", "mbamservice",
                         "crowdstrike", "csfalcon", "csagent",
                         "carbonblack", "cb", "sentinelagent",
                         "sophos", "savservice"],
        exe_path_contains: &["windows defender", "kaspersky", "norton", "avast",
                             "avg", "bitdefender", "eset", "malwarebytes",
                             "crowdstrike", "sentinelone", "carbon black", "sophos"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Cloud sync / backup ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 15,
        process_names: &["onedrive", "dropbox", "googledrivesync", "icloudservices",
                         "syncthing", "resilio-sync", "btsync",
                         "nextcloud", "owncloud"],
        exe_path_contains: &["onedrive", "dropbox", "google drive", "icloud",
                             "syncthing", "resilio"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Database tools (DBeaver, TablePlus, pgAdmin desktop) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 10,
        process_names: &["dbeaver", "tableplus", "datagrip64", "heidisql",
                         "navicat", "mysqlworkbench", "mongosh", "redis-cli"],
        exe_path_contains: &["dbeaver", "tableplus", "navicat", "heidisql"],
        cmdline_contains: &[],
        cmdline_requires_process: &[],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS svchost.exe SERVICE IDENTIFICATION
    //
    // svchost.exe hosts dozens of Windows services. Each instance has a cmdline
    // like: svchost.exe -k ServiceGroup -p -s ServiceName
    //
    // We identify services by the -s ServiceName OR -k GroupName in the cmdline.
    // IMPORTANT: process_names is EMPTY — we rely purely on cmdline matching
    // with cmdline_requires_process: &["svchost"] to avoid the +40 process score
    // that would cause ALL svchost instances to match.
    // ═══════════════════════════════════════════════════════════════════════════

    // ── RPC Endpoint Mapper ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["rpcss"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[135],
        version_from_header_prefix: None,
    },

    // ── DNS Client ──
    TechFingerprint {
        kind: ServerKind::DNS,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dnscache"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[53],
        version_from_header_prefix: None,
    },

    // ── DNS Server ──
    TechFingerprint {
        kind: ServerKind::DNS,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dns"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[53],
        version_from_header_prefix: None,
    },

    // ── DHCP Client ──
    TechFingerprint {
        kind: ServerKind::DHCP,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dhcp"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[67, 68],
        version_from_header_prefix: None,
    },

    // ── IIS / W3SVC / WAS ──
    TechFingerprint {
        kind: ServerKind::IIS,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["w3svc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::IIS,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["was"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::IIS,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["iisadmin"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[80, 443],
        version_from_header_prefix: None,
    },

    // ── SMB / LanmanServer ──
    TechFingerprint {
        kind: ServerKind::SMB,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["lanmanserver"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[445],
        version_from_header_prefix: None,
    },

    // ── SMB / LanmanWorkstation (client, but sometimes listens) ──
    TechFingerprint {
        kind: ServerKind::SMB,
        priority: 6,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["lanmanworkstation"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[445],
        version_from_header_prefix: None,
    },

    // ── FTP Service ──
    TechFingerprint {
        kind: ServerKind::FTP,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["ftpsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[21],
        version_from_header_prefix: None,
    },

    // ── OpenSSH Server (Windows feature) ──
    TechFingerprint {
        kind: ServerKind::OpenSSH,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["sshd"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[22],
        version_from_header_prefix: None,
    },

    // ── SMTP Server (IIS SMTP) ──
    TechFingerprint {
        kind: ServerKind::SMTP,
        priority: 5,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["smtpsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[25, 465, 587],
        version_from_header_prefix: None,
    },

    // ── Windows Event Log ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["eventlog"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Task Scheduler ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["schedule"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows Update ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wuauserv"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── BITS (Background Intelligent Transfer Service) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["bits"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows Firewall (MpsSvc / BFE) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["mpssvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["bfe"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── IPsec Policy Agent ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["policyagent"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── SSDP Discovery (UPnP) ──
    TechFingerprint {
        kind: ServerKind::GenericUdp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["ssdpsrv"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[1900],
        version_from_header_prefix: None,
    },

    // ── Connected Devices Platform (CDPSvc) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["cdpsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[5040],
        version_from_header_prefix: None,
    },

    // ── Windows Remote Management (WinRM) ──
    // (Already exists above, but keeping cmdline_requires_process)

    // ── Delivery Optimization (DoSvc) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dosvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[7680],
        version_from_header_prefix: None,
    },

    // ── IP Helper (iphlpsvc) — IPv6 transition, Teredo, ISATAP ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["iphlpsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── IKE and AuthIP IPsec Keying Modules ──
    TechFingerprint {
        kind: ServerKind::GenericUdp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["ikeext"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[500, 4500],
        version_from_header_prefix: None,
    },

    // ── Internet Connection Sharing (SharedAccess) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["sharedaccess"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Hyper-V services ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["hvhost"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["hns"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── DCOM Launcher ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dcomlaunch"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Network Service group (fallback for -k NetworkService) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 12,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["networkservice"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Local Service group (fallback for -k LocalService) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 12,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["localservice"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── NetSvcs group (fallback for -k netsvcs — most common group) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 12,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["netsvcs"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Local HTTP service group (for -k LocalServiceHttp) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["localservicehttp"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows Audio (AudioSrv / AudioEndpointBuilder) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["audiosrv"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows Search ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wsearch"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Bluetooth services ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["bthserv"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WLAN AutoConfig (WiFi) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wlansvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Network List Service ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["netprofm"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Network Connection Manager ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["netman"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WCMSVC (Windows Connection Manager) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wcmsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Windows Push Notifications (WpnService) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wpnservice"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── SysMain (Superfetch) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["sysmain"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Distributed Transaction Coordinator ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &["msdtc"],
        exe_path_contains: &["msdtc"],
        cmdline_contains: &["msdtc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WSA (Windows Subsystem for Android) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["wsaifabricsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Print Spooler (via svchost, rare) ──
    TechFingerprint {
        kind: ServerKind::PrintSpooler,
        priority: 8,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["spooler"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── User Manager ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["usermanager"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── WMI (Winmgmt) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["winmgmt"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Diagnostic Policy / Diagnostics services ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["dps"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Location Service ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["lfsvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── App Info (for UAC elevation) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["appinfo"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Update Orchestrator (UsoSvc) — Windows Update management ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["usosvc"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ── Token Broker ──
    TechFingerprint {
        kind: ServerKind::GenericTcp,
        priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["tokenbroker"],
        cmdline_requires_process: &["svchost"],
        http_server_contains: &[],
        http_powered_by_contains: &[],
        http_header_contains: &[],
        html_title_contains: &[],
        banner_starts_with: &[],
        banner_contains: &[],
        default_ports: &[],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DATABASES
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::PostgreSQL, priority: 10,
        process_names: &["postgres", "postgresql"],
        exe_path_contains: &["postgresql", "postgres", "pgsql"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5432], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::MySQL, priority: 10,
        process_names: &["mysqld", "mariadbd", "mariadb"],
        exe_path_contains: &["mysql", "mariadb"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["mysql", "mariadb"],
        default_ports: &[3306], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::MongoDB, priority: 10,
        process_names: &["mongod", "mongos"],
        exe_path_contains: &["mongodb", "mongo"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[27017, 27018, 27019], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Redis, priority: 10,
        process_names: &["redis-server", "redis"],
        exe_path_contains: &["redis"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["+PONG", "-ERR"], banner_contains: &["redis"],
        default_ports: &[6379], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Memcached, priority: 10,
        process_names: &["memcached"],
        exe_path_contains: &["memcached"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[11211], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::MSSQL, priority: 10,
        process_names: &["sqlservr"],
        exe_path_contains: &["mssql", "sql server"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1433, 1434], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::OracleDB, priority: 10,
        process_names: &["oracle", "tnslsnr"],
        exe_path_contains: &["oracle"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["oracle", "tns"],
        default_ports: &[1521, 1522], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CouchDB, priority: 10,
        process_names: &["couchdb", "beam.smp"],
        exe_path_contains: &["couchdb"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["couchdb"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5984], version_from_header_prefix: Some("couchdb"),
    },
    TechFingerprint {
        kind: ServerKind::Cassandra, priority: 10,
        process_names: &["cassandra"],
        exe_path_contains: &["cassandra"],
        cmdline_contains: &["cassandra"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9042, 7000, 7001], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::ClickHouse, priority: 10,
        process_names: &["clickhouse-server", "clickhouse"],
        exe_path_contains: &["clickhouse"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["clickhouse"], http_powered_by_contains: &[],
        http_header_contains: &[("x-clickhouse-server-display-name", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8123, 9000, 9440], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::InfluxDB, priority: 10,
        process_names: &["influxd"],
        exe_path_contains: &["influxdb", "influxd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["influxdb"], http_powered_by_contains: &[],
        http_header_contains: &[("x-influxdb-version", ""), ("x-influxdb-build", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8086], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Neo4j, priority: 10,
        process_names: &["neo4j"],
        exe_path_contains: &["neo4j"],
        cmdline_contains: &["neo4j"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["neo4j browser"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7474, 7687], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::ArangoDB, priority: 10,
        process_names: &["arangod", "arangodb"],
        exe_path_contains: &["arangodb"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["arangodb"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["arangodb"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8529], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CockroachDB, priority: 10,
        process_names: &["cockroach"],
        exe_path_contains: &["cockroach"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["cockroachdb"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[26257, 8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Etcd, priority: 10,
        process_names: &["etcd"],
        exe_path_contains: &["etcd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-etcd-cluster-id", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[2379, 2380], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Consul, priority: 10,
        process_names: &["consul"],
        exe_path_contains: &["consul"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-consul-index", "")], html_title_contains: &["consul"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8500, 8501, 8600], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Vault, priority: 10,
        process_names: &["vault"],
        exe_path_contains: &["vault"],
        cmdline_contains: &["server"], cmdline_requires_process: &["vault"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-vault-token", "")], html_title_contains: &["vault"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8200], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::RethinkDB, priority: 10,
        process_names: &["rethinkdb"],
        exe_path_contains: &["rethinkdb"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["rethinkdb"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[28015, 8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::TiDB, priority: 10,
        process_names: &["tidb-server"],
        exe_path_contains: &["tidb"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4000, 10080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::ScyllaDB, priority: 10,
        process_names: &["scylla"],
        exe_path_contains: &["scylla"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9042, 19042], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::DGraph, priority: 10,
        process_names: &["dgraph"],
        exe_path_contains: &["dgraph"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["dgraph"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080, 9080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::PgBouncer, priority: 10,
        process_names: &["pgbouncer"],
        exe_path_contains: &["pgbouncer"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6432], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::QuestDB, priority: 10,
        process_names: &["questdb"],
        exe_path_contains: &["questdb"],
        cmdline_contains: &["questdb"], cmdline_requires_process: &["java"],
        http_server_contains: &["questdb"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["questdb"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000, 8812, 9009], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Firebird, priority: 10,
        process_names: &["firebird", "fbserver", "fbguard"],
        exe_path_contains: &["firebird"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3050], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Elasticsearch, priority: 10,
        process_names: &["elasticsearch", "opensearch"],
        exe_path_contains: &["elasticsearch", "opensearch"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-elastic-product", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["elasticsearch", "opensearch"],
        default_ports: &[9200, 9300], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::MeiliSearch, priority: 10,
        process_names: &["meilisearch"],
        exe_path_contains: &["meilisearch"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["meilisearch"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7700], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Solr, priority: 10,
        process_names: &["solr"],
        exe_path_contains: &["solr"],
        cmdline_contains: &["solr"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["solr"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8983], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MESSAGE BROKERS & QUEUES
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["rabbitmq-server", "beam.smp"],
        exe_path_contains: &["rabbitmq"],
        cmdline_contains: &["rabbit"], cmdline_requires_process: &["beam.smp", "erl"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["rabbitmq"],
        banner_starts_with: &["AMQP"], banner_contains: &[],
        default_ports: &[5672, 15672, 25672], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["kafka"],
        exe_path_contains: &["kafka"],
        cmdline_contains: &["kafka"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9092, 9093], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["activemq"],
        exe_path_contains: &["activemq"],
        cmdline_contains: &["activemq"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["activemq"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[61616, 8161], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nats-server", "nats"],
        exe_path_contains: &["nats"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["INFO {"], banner_contains: &["nats"],
        default_ports: &[4222, 8222], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mosquitto"],
        exe_path_contains: &["mosquitto"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1883, 8883, 9001], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nsqd", "nsqlookupd"],
        exe_path_contains: &["nsq"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["nsq"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["nsq"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4150, 4151, 4160, 4161], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["pulsar"],
        exe_path_contains: &["pulsar"],
        cmdline_contains: &["pulsar"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6650, 8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["beanstalkd"],
        exe_path_contains: &["beanstalkd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[11300], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MONITORING & OBSERVABILITY
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["prometheus"],
        exe_path_contains: &["prometheus"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["prometheus"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9090], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["grafana", "grafana-server"],
        exe_path_contains: &["grafana"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["grafana"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["kibana"],
        exe_path_contains: &["kibana"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("kbn-name", ""), ("kbn-version", "")], html_title_contains: &["kibana", "elastic"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5601], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["logstash"],
        exe_path_contains: &["logstash"],
        cmdline_contains: &["logstash"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5044, 9600], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["fluentd", "fluentbit", "fluent-bit"],
        exe_path_contains: &["fluentd", "fluent-bit"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[24224, 2020], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["jaeger"],
        exe_path_contains: &["jaeger"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["jaeger"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[16686, 14268], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["zipkin"],
        exe_path_contains: &["zipkin"],
        cmdline_contains: &["zipkin"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["zipkin"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9411], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["alertmanager"],
        exe_path_contains: &["alertmanager"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["alertmanager"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9093], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["netdata"],
        exe_path_contains: &["netdata"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["netdata"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["netdata"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[19999], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["uptime-kuma"],
        exe_path_contains: &["uptime-kuma"],
        cmdline_contains: &["uptime-kuma"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["uptime kuma"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3001], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["graylog"],
        exe_path_contains: &["graylog"],
        cmdline_contains: &["graylog"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-graylog-node-id", "")], html_title_contains: &["graylog"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000, 12201], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["zabbix_server", "zabbix_agentd"],
        exe_path_contains: &["zabbix"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["zabbix"],
        banner_starts_with: &["ZBXD"], banner_contains: &[],
        default_ports: &[10051, 10050], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["telegraf"],
        exe_path_contains: &["telegraf"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8125], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // CONTAINER & ORCHESTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["dockerd", "docker"],
        exe_path_contains: &["docker"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["docker"], http_powered_by_contains: &[],
        http_header_contains: &[("docker-experimental", ""), ("ostype", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[2375, 2376], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["containerd"],
        exe_path_contains: &["containerd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[10010], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["kube-apiserver"],
        exe_path_contains: &["kubernetes"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6443, 8443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["portainer"],
        exe_path_contains: &["portainer"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["portainer"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000, 9443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::DNS, priority: 10,
        process_names: &["coredns"],
        exe_path_contains: &["coredns"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[53, 9153], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["nomad"],
        exe_path_contains: &["nomad"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-nomad-knownleader", "")], html_title_contains: &["nomad"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4646, 4647, 4648], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // CI/CD & DEVOPS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["gitea"],
        exe_path_contains: &["gitea"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["gitea"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["gitea"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["gogs"],
        exe_path_contains: &["gogs"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["gogs"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["gitlab-workhorse", "gitlab-rails", "puma"],
        exe_path_contains: &["gitlab"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["gitlab-workhorse"], http_powered_by_contains: &[],
        http_header_contains: &[("x-gitlab-meta", "")], html_title_contains: &["gitlab"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443, 8929], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["drone-server", "drone"],
        exe_path_contains: &["drone"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["drone"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["teamcity"],
        exe_path_contains: &["teamcity"],
        cmdline_contains: &["teamcity"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["teamcity"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8111], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["concourse"],
        exe_path_contains: &["concourse"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["concourse"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["argocd-server"],
        exe_path_contains: &["argocd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["argo cd"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080, 8443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["harbor-core"],
        exe_path_contains: &["harbor"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["harbor"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["nexus"],
        exe_path_contains: &["nexus", "sonatype"],
        cmdline_contains: &["nexus"], cmdline_requires_process: &["java"],
        http_server_contains: &["nexus"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["nexus repository"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8081], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["verdaccio"],
        exe_path_contains: &["verdaccio"],
        cmdline_contains: &["verdaccio"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["verdaccio"],
        http_header_contains: &[], html_title_contains: &["verdaccio"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4873], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["gocd"],
        exe_path_contains: &["gocd", "go-server"],
        cmdline_contains: &["go.jar"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["gocd"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8153, 8154], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DEVELOPMENT TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["jupyter-notebook", "jupyter-lab", "jupyter"],
        exe_path_contains: &["jupyter"],
        cmdline_contains: &["jupyter"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["tornadoserver"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["jupyter"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8888], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["code-server"],
        exe_path_contains: &["code-server"],
        cmdline_contains: &["code-server"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["code-server", "code - oss"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["storybook"],
        exe_path_contains: &["storybook"],
        cmdline_contains: &["storybook"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["storybook"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6006], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["webpack"],
        exe_path_contains: &["webpack"],
        cmdline_contains: &["webpack"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080, 9000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["vite"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5173], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["ngrok"],
        exe_path_contains: &["ngrok"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("ngrok-agent-ips", "")], html_title_contains: &["ngrok"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4040], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MEDIA SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["plexmediaserver", "plex media server"],
        exe_path_contains: &["plex"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-plex-protocol", "")], html_title_contains: &["plex"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[32400], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["jellyfin"],
        exe_path_contains: &["jellyfin"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-emby-authorization", "")], html_title_contains: &["jellyfin"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8096, 8920], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["embyserver", "emby"],
        exe_path_contains: &["emby"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["emby"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8096, 8920], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["navidrome"],
        exe_path_contains: &["navidrome"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["navidrome"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4533], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["icecast"],
        exe_path_contains: &["icecast"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["icecast"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["icecast"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: Some("icecast"),
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mumble-server", "murmurd"],
        exe_path_contains: &["mumble"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[64738], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ts3server", "teamspeak"],
        exe_path_contains: &["teamspeak"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["TS3"], banner_contains: &[],
        default_ports: &[9987, 10011, 30033], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // HOME AUTOMATION & IOT
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["hass", "homeassistant"],
        exe_path_contains: &["homeassistant", "home-assistant"],
        cmdline_contains: &["homeassistant"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["home assistant"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8123], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["node-red"],
        exe_path_contains: &["node-red"],
        cmdline_contains: &["node-red"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["node-red"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1880], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["pihole-ftl"],
        exe_path_contains: &["pihole"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["pi-hole"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 53], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["adguardhome"],
        exe_path_contains: &["adguardhome"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["adguard home"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000, 53], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["homebridge"],
        exe_path_contains: &["homebridge"],
        cmdline_contains: &["homebridge"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["homebridge"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8581, 51826], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // VPN & NETWORK TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["openvpn"],
        exe_path_contains: &["openvpn"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1194], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wireguard", "wg"],
        exe_path_contains: &["wireguard"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[51820], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["tailscaled"],
        exe_path_contains: &["tailscale"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[41641], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["zerotier-one", "zerotier"],
        exe_path_contains: &["zerotier"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9993], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["headscale"],
        exe_path_contains: &["headscale"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["headscale"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MAIL SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["postfix", "master"],
        exe_path_contains: &["postfix"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220 "], banner_contains: &["postfix", "esmtp"],
        default_ports: &[25, 587, 465], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["exim", "exim4"],
        exe_path_contains: &["exim"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220 "], banner_contains: &["exim"],
        default_ports: &[25, 587, 465], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["sendmail"],
        exe_path_contains: &["sendmail"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220 "], banner_contains: &["sendmail"],
        default_ports: &[25, 587], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["dovecot"],
        exe_path_contains: &["dovecot"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["* OK "], banner_contains: &["dovecot"],
        default_ports: &[143, 993, 110, 995], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["hmailserver"],
        exe_path_contains: &["hmailserver"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220 "], banner_contains: &["hmailserver"],
        default_ports: &[25, 587, 143, 110], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // GAME SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::Minecraft, priority: 10,
        process_names: &["java"],
        exe_path_contains: &[],
        cmdline_contains: &["minecraft", "spigot", "paper", "bukkit", "forge"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[25565], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Minecraft, priority: 10,
        process_names: &["bedrock_server"],
        exe_path_contains: &["bedrock"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[19132], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Factorio, priority: 10,
        process_names: &["factorio"],
        exe_path_contains: &["factorio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[34197], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Terraria, priority: 10,
        process_names: &["terrariaserver", "tshock"],
        exe_path_contains: &["terraria"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7777], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Valheim, priority: 10,
        process_names: &["valheim_server", "valheim"],
        exe_path_contains: &["valheim"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[2456, 2457], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::SourceEngine, priority: 10,
        process_names: &["srcds", "srcds_linux", "srcds_run"],
        exe_path_contains: &["srcds"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[27015, 27016], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::RustGame, priority: 10,
        process_names: &["rustdedicated", "rust"],
        exe_path_contains: &["rustdedicated"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[28015, 28016], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::ArkServer, priority: 10,
        process_names: &["arkserver", "shootergame"],
        exe_path_contains: &["ark"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7777, 27015], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WEB SERVERS (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["caddy"],
        exe_path_contains: &["caddy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["caddy"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["caddy"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443, 2019], version_from_header_prefix: Some("caddy"),
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["traefik"],
        exe_path_contains: &["traefik"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["traefik"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["traefik"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443, 8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["envoy"],
        exe_path_contains: &["envoy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["envoy"], http_powered_by_contains: &[],
        http_header_contains: &[("x-envoy-upstream-service-time", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9901, 10000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["lighttpd"],
        exe_path_contains: &["lighttpd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["lighttpd"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: Some("lighttpd"),
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["varnishd"],
        exe_path_contains: &["varnish"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["varnish"], http_powered_by_contains: &[],
        http_header_contains: &[("x-varnish", ""), ("via", "varnish")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6081, 6082], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["squid"],
        exe_path_contains: &["squid"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["squid"], http_powered_by_contains: &[],
        http_header_contains: &[("x-squid-error", "")], html_title_contains: &["squid"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3128, 3129], version_from_header_prefix: Some("squid"),
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["litespeed", "lsws", "lshttpd"],
        exe_path_contains: &["litespeed", "lsws"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["litespeed"], http_powered_by_contains: &[],
        http_header_contains: &[("x-litespeed-cache", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443, 7080], version_from_header_prefix: Some("litespeed"),
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["tengine"],
        exe_path_contains: &["tengine"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["tengine"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: Some("tengine"),
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["h2o"],
        exe_path_contains: &["h2o"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["h2o"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: Some("h2o"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // BACKEND FRAMEWORKS (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["next"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["next.js"],
        http_header_contains: &[("x-nextjs-cache", ""), ("x-nextjs-matched-path", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["nuxt"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["nuxt"],
        http_header_contains: &[("x-nuxt-cache", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["remix"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["remix"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["astro"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4321], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["svelte-kit", "sveltekit"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["sveltekit"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5173], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["gatsby"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["gatsby"],
        http_header_contains: &[("x-gatsby-cache", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000, 9000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["fastify"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["fastify"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["koa"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["koa"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::NodeJs, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["hapi"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &["hapi"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Python, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["fastapi"], cmdline_requires_process: &["python", "python3", "uvicorn"],
        http_server_contains: &["uvicorn"], http_powered_by_contains: &["fastapi"],
        http_header_contains: &[], html_title_contains: &["fastapi"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Python, priority: 20,
        process_names: &["uvicorn", "gunicorn", "hypercorn"],
        exe_path_contains: &[],
        cmdline_contains: &["starlette"], cmdline_requires_process: &["python", "python3", "uvicorn"],
        http_server_contains: &["uvicorn"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Python, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["flask"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["werkzeug"], http_powered_by_contains: &["flask"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Python, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["tornado"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["tornadoserver"], http_powered_by_contains: &["tornado"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8888], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::Python, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["bottle"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &["bottle"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["laravel"], cmdline_requires_process: &["php", "php-fpm"],
        http_server_contains: &[], http_powered_by_contains: &["laravel"],
        http_header_contains: &[("x-powered-by", "laravel")], html_title_contains: &["laravel"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["symfony"], cmdline_requires_process: &["php", "php-fpm"],
        http_server_contains: &[], http_powered_by_contains: &["symfony"],
        http_header_contains: &[("x-debug-token", "")], html_title_contains: &["symfony"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["codeigniter"],
        cmdline_contains: &["codeigniter"], cmdline_requires_process: &["php"],
        http_server_contains: &[], http_powered_by_contains: &["codeigniter"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["sinatra"], cmdline_requires_process: &["ruby"],
        http_server_contains: &[], http_powered_by_contains: &["sinatra"],
        http_header_contains: &[("x-powered-by", "sinatra")], html_title_contains: &["sinatra"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4567], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &["gin"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &["gin"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["fiber"], http_powered_by_contains: &["fiber"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &["echo"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1323], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["micronaut"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &["micronaut"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["quarkus"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &["quarkus"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["play"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &["play"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["kestrel"], http_powered_by_contains: &["asp.net core"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5000, 5001], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &["actix"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["actix-web"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["rocket"], http_powered_by_contains: &["rocket"],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["warp"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3030], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // FILE SHARING & SYNC
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["syncthing"],
        exe_path_contains: &["syncthing"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["syncthing"], http_powered_by_contains: &[],
        http_header_contains: &[("x-syncthing-id", "")], html_title_contains: &["syncthing"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8384, 22000], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["nextcloud"],
        exe_path_contains: &["nextcloud"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-nextcloud-version", "")], html_title_contains: &["nextcloud"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["owncloud"],
        exe_path_contains: &["owncloud"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["owncloud"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["seafile"],
        exe_path_contains: &["seafile"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["seafile"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000, 8082], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["minio"],
        exe_path_contains: &["minio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["minio"], http_powered_by_contains: &[],
        http_header_contains: &[("x-amz-request-id", "")], html_title_contains: &["minio"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000, 9001], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::FTP, priority: 10,
        process_names: &["filezilla server", "filezillaserver"],
        exe_path_contains: &["filezilla server"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220-FileZilla", "220 FileZilla"], banner_contains: &["filezilla"],
        default_ports: &[21], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS DESKTOP APPS WITH SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["everything"],
        exe_path_contains: &["everything"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["everything"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["everything"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["bitwarden"],
        exe_path_contains: &["bitwarden"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["bitwarden"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["vaultwarden"],
        exe_path_contains: &["vaultwarden"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["vaultwarden"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 3012], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::VNC, priority: 10,
        process_names: &["tvnserver", "tightvnc"],
        exe_path_contains: &["tightvnc"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["RFB "], banner_contains: &[],
        default_ports: &[5900, 5800], version_from_header_prefix: None,
    },
    TechFingerprint {
        kind: ServerKind::VNC, priority: 10,
        process_names: &["winvnc", "ultravnc"],
        exe_path_contains: &["ultravnc", "uvnc"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["RFB "], banner_contains: &[],
        default_ports: &[5900, 5800], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MISC SERVICES (user-system specific)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Android Debug Bridge ──
    TechFingerprint {
        kind: ServerKind::AndroidAdb, priority: 10,
        process_names: &["adb"],
        exe_path_contains: &["adb"],
        cmdline_contains: &["fork-server"], cmdline_requires_process: &["adb"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5037], version_from_header_prefix: None,
    },

    // ── Apple Bonjour / mDNSResponder ──
    TechFingerprint {
        kind: ServerKind::Bonjour, priority: 10,
        process_names: &["mdnsresponder"],
        exe_path_contains: &["bonjour"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5353, 5354], version_from_header_prefix: None,
    },

    // ── NordVPN Service ──
    TechFingerprint {
        kind: ServerKind::NordVPN, priority: 10,
        process_names: &["nordvpn-service", "nordvpn"],
        exe_path_contains: &["nordvpn"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Apple Mobile Device Service ──
    TechFingerprint {
        kind: ServerKind::AppleMobileDevice, priority: 10,
        process_names: &["applemobiledeviceservice"],
        exe_path_contains: &["apple\\mobile device support", "apple/mobile device support"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[27015], version_from_header_prefix: None,
    },

    // ── Intel SUR (Software Update Retrieval) ──
    TechFingerprint {
        kind: ServerKind::IntelSUR, priority: 10,
        process_names: &["esrv"],
        exe_path_contains: &["intel\\sur", "intel/sur"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Hyper-V Virtual Machine Management ──
    TechFingerprint {
        kind: ServerKind::HyperVManager, priority: 10,
        process_names: &["vmms"],
        exe_path_contains: &["vmms"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[2179], version_from_header_prefix: None,
    },

    // ── Windows TCPSVCS (Simple TCP/IP Services) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["tcpsvcs"],
        exe_path_contains: &["tcpsvcs"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7, 9, 13, 17, 19], version_from_header_prefix: None,
    },

    // ── AdGuard Desktop Service ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["adguardsvc"],
        exe_path_contains: &["adguard"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS KERNEL (System/PID 4) OWNED PORTS
    // These have process_name "system" with no exe_path or cmdline.
    // ═══════════════════════════════════════════════════════════════════════════

    // ── HTTP.sys (Windows HTTP API / IIS kernel) ──
    TechFingerprint {
        kind: ServerKind::IIS, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["microsoft-httpapi", "microsoft-iis"],
        http_powered_by_contains: &["asp.net"],
        http_header_contains: &[("x-aspnet-version", "")],
        html_title_contains: &[],
        banner_starts_with: &["HTTP/"], banner_contains: &[],
        default_ports: &[80, 443, 8443, 47001],
        version_from_header_prefix: Some("microsoft-httpapi"),
    },

    // ── SMB (Server Message Block) ──
    TechFingerprint {
        kind: ServerKind::SMB, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[139, 445],
        version_from_header_prefix: None,
    },

    // ── WinRM (Windows Remote Management) ──
    TechFingerprint {
        kind: ServerKind::WinRM, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["microsoft-httpapi"],
        http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5985, 5986],
        version_from_header_prefix: None,
    },

    // ── WSD (Web Services Discovery) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5357, 5358],
        version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS SYSTEM SERVICES (additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Runtime Broker ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["runtimebroker"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── COM Surrogate ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dllhost"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── WMI Provider Host ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wmiprvse"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Credential Guard ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["lsaiso"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Font Driver Host ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["fontdrvhost"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Desktop Window Manager ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dwm"],
        exe_path_contains: &[],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // GAMING / ENTERTAINMENT PLATFORMS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Steam ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["steam", "steamwebhelper", "steamservice"],
        exe_path_contains: &["steam"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Epic Games Launcher ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["epicgameslauncher", "epiconlineservices", "eosoverlaypluginprocesshost"],
        exe_path_contains: &["epic games"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── GOG Galaxy ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["galaxyclient", "galaxyclientservice"],
        exe_path_contains: &["gog galaxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Battle.net ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["battle.net"],
        exe_path_contains: &["battle.net"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── EA App / Origin ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ealauncher", "eadesktop", "origin"],
        exe_path_contains: &["electronic arts"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Ubisoft Connect ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ubisoftconnect", "ubisoftgamelauncher"],
        exe_path_contains: &["ubisoft"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Xbox Game Bar ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["gamebar", "gamebarft"],
        exe_path_contains: &["gamebar"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Riot Client ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["riotclientservices", "riotclientux"],
        exe_path_contains: &["riot games"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Discord (standalone, local RPC) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["discord"],
        exe_path_contains: &["discord"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6463], version_from_header_prefix: None,
    },
    // ── Spotify ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["spotify"],
        exe_path_contains: &["spotify"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // BROWSERS (standalone fingerprints for DevTools/debug ports)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Firefox ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["firefox"],
        exe_path_contains: &["mozilla firefox"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // COMMUNICATION APPS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Slack (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["slack"],
        exe_path_contains: &["slack"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Microsoft Teams (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["teams", "ms-teams"],
        exe_path_contains: &["teams"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Zoom ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["zoom"],
        exe_path_contains: &["zoom"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Skype ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["skype"],
        exe_path_contains: &["skype"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── WhatsApp (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["whatsapp"],
        exe_path_contains: &["whatsapp"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Telegram (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["telegram"],
        exe_path_contains: &["telegram"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Signal (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["signal"],
        exe_path_contains: &["signal"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Webex ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ciscowebex", "webexmta"],
        exe_path_contains: &["webex"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // REMOTE ACCESS TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── TeamViewer ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["teamviewer", "teamviewer_service"],
        exe_path_contains: &["teamviewer"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5938], version_from_header_prefix: None,
    },
    // ── AnyDesk ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["anydesk"],
        exe_path_contains: &["anydesk"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[7070], version_from_header_prefix: None,
    },
    // ── Parsec (game streaming) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["parsecd", "parsecvdd"],
        exe_path_contains: &["parsec"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Sunshine (Moonlight game streaming host) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["sunshine"],
        exe_path_contains: &["sunshine"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[47984, 47989, 47990, 48010], version_from_header_prefix: None,
    },
    // ── RustDesk ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["rustdesk"],
        exe_path_contains: &["rustdesk"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[21115, 21116, 21117, 21118], version_from_header_prefix: None,
    },
    // ── Chrome Remote Desktop ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["remoting_host"],
        exe_path_contains: &["chrome remote desktop"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── RealVNC (standalone) ──
    TechFingerprint {
        kind: ServerKind::VNC, priority: 10,
        process_names: &["vncviewer"],
        exe_path_contains: &["realvnc"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["RFB "], banner_contains: &["vnc"],
        default_ports: &[5900], version_from_header_prefix: None,
    },
    // ── NoMachine ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nxserver", "nxnode"],
        exe_path_contains: &["nomachine"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4000], version_from_header_prefix: None,
    },
    // ── WinSCP ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["winscp"],
        exe_path_contains: &["winscp"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── PuTTY / Pageant / Plink ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["putty", "pageant", "plink"],
        exe_path_contains: &["putty"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MobaXterm ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mobaxterm"],
        exe_path_contains: &["mobaxterm"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // TORRENT / DOWNLOAD CLIENTS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── qBittorrent (with web UI) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["qbittorrent"],
        exe_path_contains: &["qbittorrent"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["qbittorrent"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    // ── uTorrent ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["utorrent"],
        exe_path_contains: &["utorrent"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Transmission (web UI port 9091) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["transmission-daemon", "transmission-qt"],
        exe_path_contains: &["transmission"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["transmission"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9091], version_from_header_prefix: None,
    },
    // ── Deluge (web UI port 8112) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["deluge", "deluged"],
        exe_path_contains: &["deluge"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["deluge"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8112], version_from_header_prefix: None,
    },
    // ── BitTorrent ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["bittorrent"],
        exe_path_contains: &["bittorrent"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── aria2 (RPC on port 6800) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["aria2c"],
        exe_path_contains: &["aria2"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6800], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MEDIA PLAYERS WITH SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── VLC (HTTP interface) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["vlc"],
        exe_path_contains: &["videolan"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["vlc"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    // ── Kodi (web interface) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["kodi"],
        exe_path_contains: &["kodi"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["kodi"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },
    // ── foobar2000 ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["foobar2000"],
        exe_path_contains: &["foobar2000"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MusicBee ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["musicbee"],
        exe_path_contains: &["musicbee"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Calibre (content server) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["calibre"],
        exe_path_contains: &["calibre"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["calibre"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["calibre"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // OBS STUDIO
    // ═══════════════════════════════════════════════════════════════════════════

    // ── OBS Studio (WebSocket port 4455) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["obs64", "obs32", "obs-studio"],
        exe_path_contains: &["obs-studio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4455], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // VIRTUALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    // ── VirtualBox ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["vboxsvc", "vboxheadless", "vboxnetdhcp", "vboxnetnat"],
        exe_path_contains: &["virtualbox"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[18083], version_from_header_prefix: None,
    },
    // ── VMware ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["vmware-hostd", "vmnat", "vmnetdhcp", "vmware"],
        exe_path_contains: &["vmware"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[443, 8697], version_from_header_prefix: None,
    },
    // ── QEMU ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["qemu-system-x86_64", "qemu-system-x86", "qemu"],
        exe_path_contains: &["qemu"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── WSL ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wslhost", "wsl"],
        exe_path_contains: &["wsl"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // HARDWARE CONTROL SOFTWARE
    // ═══════════════════════════════════════════════════════════════════════════

    // ── NVIDIA Container ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nvcontainer", "nvdisplay.container"],
        exe_path_contains: &["nvidia"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── NVIDIA GeForce Experience ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nvidia share", "nvidia web helper", "gfexperience"],
        exe_path_contains: &["nvidia"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── AMD Software ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["radeonsoftware", "amdrsserv", "amddvr"],
        exe_path_contains: &["amd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Razer Synapse ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["razersynapse", "razer central", "rzsdkservice"],
        exe_path_contains: &["razer"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Corsair iCUE ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["icue", "corsair"],
        exe_path_contains: &["corsair"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Logitech G Hub ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["lghub", "lghub_agent", "logi_lamparray_service"],
        exe_path_contains: &["logi"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── SteelSeries GG ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["steelseriesgg", "steelseriesengine"],
        exe_path_contains: &["steelseries"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Elgato Stream Deck ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["streamdeck"],
        exe_path_contains: &["elgato\\stream deck"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MSI Dragon Center ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["msi_dragoncenter", "msiservice"],
        exe_path_contains: &["msi"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ASUS Armoury Crate ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["armourycrate", "asusoptimization"],
        exe_path_contains: &["asus"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Intel Driver & Support Assistant ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dsa"],
        exe_path_contains: &["intel\\driver"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // CLOUD SYNC (additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Google Drive (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["googledrivesync", "googledrivefs"],
        exe_path_contains: &["google\\drive"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── iCloud (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["icloud", "icloudservices"],
        exe_path_contains: &["icloud"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Box Sync ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["box", "boxsync"],
        exe_path_contains: &["box"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MEGA Sync ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["megasync"],
        exe_path_contains: &["mega"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── pCloud ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["pcloud"],
        exe_path_contains: &["pcloud"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // PASSWORD MANAGERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── KeePassXC ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["keepassxc"],
        exe_path_contains: &["keepassxc"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── 1Password ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["1password"],
        exe_path_contains: &["1password"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── LastPass ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["lastpass"],
        exe_path_contains: &["lastpass"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── NordPass ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nordpass"],
        exe_path_contains: &["nordpass"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Dashlane ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dashlane"],
        exe_path_contains: &["dashlane"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY / ANTIVIRUS (additional standalone entries)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Malwarebytes (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mbamservice", "mbam"],
        exe_path_contains: &["malwarebytes"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Norton (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["norton", "ns"],
        exe_path_contains: &["norton"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── McAfee ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mcshield", "mfewc", "mcafee"],
        exe_path_contains: &["mcafee"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Kaspersky (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["avp", "avpui"],
        exe_path_contains: &["kaspersky"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ESET ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ekrn", "egui"],
        exe_path_contains: &["eset"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Bitdefender ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["bdagent", "bdservicehost", "vsserv"],
        exe_path_contains: &["bitdefender"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Avast / AVG ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["avastsvc", "avgsvc", "avgui"],
        exe_path_contains: &["avast"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── CrowdStrike (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["csagent", "csfalconservice"],
        exe_path_contains: &["crowdstrike"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Sophos (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["sophoshealth", "sophosupd"],
        exe_path_contains: &["sophos"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Webroot ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wrsa"],
        exe_path_contains: &["webroot"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // VPN SERVICES (additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── ExpressVPN ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["expressvpn", "expressvpnservice"],
        exe_path_contains: &["expressvpn"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Surfshark ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["surfshark"],
        exe_path_contains: &["surfshark"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ProtonVPN ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["protonvpn", "protonvpnservice"],
        exe_path_contains: &["protonvpn"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── CyberGhost VPN ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["cyberghostvpn"],
        exe_path_contains: &["cyberghost"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Mullvad VPN ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mullvad-daemon", "mullvad-vpn"],
        exe_path_contains: &["mullvad"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Cloudflare WARP ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["warp-svc", "cloudflare warp"],
        exe_path_contains: &["cloudflare"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Private Internet Access ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["pia-service", "pia-client"],
        exe_path_contains: &["private internet access"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DEVELOPMENT TOOLS (additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Postman (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["postman"],
        exe_path_contains: &["postman"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Insomnia (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["insomnia"],
        exe_path_contains: &["insomnia"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MongoDB Compass ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mongodbcompass"],
        exe_path_contains: &["mongodb compass"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── RedisInsight ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["redisinsight"],
        exe_path_contains: &["redisinsight"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["redisinsight"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5540], version_from_header_prefix: None,
    },
    // ── Fiddler (proxy port 8866) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["fiddler"],
        exe_path_contains: &["fiddler"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8866], version_from_header_prefix: None,
    },
    // ── Charles Proxy (proxy port 8888) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["charles"],
        exe_path_contains: &["charles"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8888], version_from_header_prefix: None,
    },
    // ── mitmproxy ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["mitmproxy", "mitmdump", "mitmweb"],
        exe_path_contains: &["mitmproxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080, 8081], version_from_header_prefix: None,
    },
    // ── Wireshark / tshark / dumpcap ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wireshark", "tshark", "dumpcap"],
        exe_path_contains: &["wireshark"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // IDEs (additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Visual Studio ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["devenv"],
        exe_path_contains: &["microsoft visual studio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Android Studio ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["studio64", "studio"],
        exe_path_contains: &["android studio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Eclipse ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["eclipse"],
        exe_path_contains: &["eclipse"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Sublime Text ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["sublime_text"],
        exe_path_contains: &["sublime text"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Notepad++ ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["notepad++"],
        exe_path_contains: &["notepad++"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // GAME DEVELOPMENT
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Unity ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["unity"],
        exe_path_contains: &["unity"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Unreal Editor ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["unrealengine", "ue4editor", "ue5editor"],
        exe_path_contains: &["unreal"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Godot ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["godot"],
        exe_path_contains: &["godot"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Blender ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["blender"],
        exe_path_contains: &["blender"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // ERLANG RUNTIME
    // ═══════════════════════════════════════════════════════════════════════════

    // ── EPMD (Erlang Port Mapper Daemon) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["epmd"],
        exe_path_contains: &["erlang"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4369], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // PRINTER / SCANNER SOFTWARE
    // ═══════════════════════════════════════════════════════════════════════════

    // ── HP Smart ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["hpsmart", "hpnetworkcommunicator"],
        exe_path_contains: &["hp"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Canon IJ Network ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["cnijnetwork"],
        exe_path_contains: &["canon"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Epson Scanner ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["epson"],
        exe_path_contains: &["epson"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // ASUS-SPECIFIC SOFTWARE
    // ═══════════════════════════════════════════════════════════════════════════

    // ── GlideX ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["glidexservice", "glidexnearservice"],
        exe_path_contains: &["glidex"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ASUS Software Manager ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["asussoftwaremanager"],
        exe_path_contains: &["asussoftwaremanager"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── MyASUS ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["myasus"],
        exe_path_contains: &["myasus"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ASUS System Control Interface ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["asussci"],
        exe_path_contains: &["asus"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // MISC COMMON PROCESSES
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Git daemon ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["git-daemon"],
        exe_path_contains: &["git"],
        cmdline_contains: &["daemon"], cmdline_requires_process: &["git"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9418], version_from_header_prefix: None,
    },
    // ── Python HTTP server ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["http.server"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    // ── PHP built-in server ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["-S"], cmdline_requires_process: &["php"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },
    // ── Ruby WEBrick ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["webrick"], cmdline_requires_process: &["ruby"],
        http_server_contains: &["webrick"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },
    // ── Rust cargo watch ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["watch"], cmdline_requires_process: &["cargo"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── .NET SDK (standalone) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dotnet"],
        exe_path_contains: &["dotnet"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Java generic ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["java", "javaw"],
        exe_path_contains: &["java"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── PowerShell ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["powershell", "pwsh"],
        exe_path_contains: &["powershell"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Chocolatey ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["choco"],
        exe_path_contains: &["chocolatey"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── Windows Terminal ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["windowsterminal"],
        exe_path_contains: &["windowsterminal"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },
    // ── ConEmu ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["conemu", "conemu64"],
        exe_path_contains: &["conemu"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // ENTERPRISE & NETWORK PROTOCOLS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── LDAP Server (OpenLDAP) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["slapd"],
        exe_path_contains: &["openldap", "slapd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["ldap"],
        default_ports: &[389, 636], version_from_header_prefix: None,
    },

    // ── Kerberos KDC ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["krb5kdc", "kadmind"],
        exe_path_contains: &["kerberos", "krb5"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[88, 749], version_from_header_prefix: None,
    },

    // ── SNMP Daemon ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["snmpd", "snmptrapd"],
        exe_path_contains: &["snmp"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[161, 162], version_from_header_prefix: None,
    },

    // ── NTP Server ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ntpd", "chronyd", "w32tm"],
        exe_path_contains: &["ntp", "chrony"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[123], version_from_header_prefix: None,
    },

    // ── TFTP Server ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["tftpd", "tftpd64", "tftpd32", "in.tftpd"],
        exe_path_contains: &["tftp"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[69], version_from_header_prefix: None,
    },

    // ── Syslog Daemon ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["syslogd", "rsyslogd", "syslog-ng"],
        exe_path_contains: &["syslog", "rsyslog"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[514], version_from_header_prefix: None,
    },

    // ── RADIUS Server ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["radiusd", "freeradius"],
        exe_path_contains: &["radius", "freeradius"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1812, 1813], version_from_header_prefix: None,
    },

    // ── BGP Daemon (FRRouting / BIRD) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["bgpd", "bird", "frr"],
        exe_path_contains: &["frr", "bird"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[179], version_from_header_prefix: None,
    },

    // ── OSPF Daemon (FRRouting) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["ospfd", "ospf6d"],
        exe_path_contains: &["frr", "quagga"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Samba (nmbd companion) ──
    TechFingerprint {
        kind: ServerKind::SMB, priority: 10,
        process_names: &["nmbd"],
        exe_path_contains: &["samba"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[137, 138], version_from_header_prefix: None,
    },

    // ── NFS Server ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nfsd", "rpc.nfsd", "rpc.mountd", "rpc.statd"],
        exe_path_contains: &["nfs"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[2049, 111], version_from_header_prefix: None,
    },

    // ── iSCSI Target ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["iscsitarget", "tgtd", "lio-target"],
        exe_path_contains: &["iscsi", "tgt"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3260], version_from_header_prefix: None,
    },

    // ── CUPS (Print Server) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["cupsd"],
        exe_path_contains: &["cups"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["cups"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["cups"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[631], version_from_header_prefix: Some("cups"),
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DATABASE ADMIN TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Adminer ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["adminer"],
        cmdline_contains: &["adminer"], cmdline_requires_process: &["php"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["adminer"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ── phpMyAdmin ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["phpmyadmin"],
        cmdline_contains: &["phpmyadmin"], cmdline_requires_process: &["php"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["phpmyadmin"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 8080], version_from_header_prefix: None,
    },

    // ── Robo 3T / Studio 3T ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["robo3t", "studio3t"],
        exe_path_contains: &["robo 3t", "studio 3t", "3t"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── DbVisualizer ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["dbvisualizer", "dbvis"],
        exe_path_contains: &["dbvisualizer"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── SQL Developer ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["sqldeveloper"],
        exe_path_contains: &["sqldeveloper"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Navicat ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["navicat"],
        exe_path_contains: &["navicat"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── HeidiSQL ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["heidisql"],
        exe_path_contains: &["heidisql"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── SQLyog ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["sqlyog"],
        exe_path_contains: &["sqlyog"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── DataGrip ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["datagrip64", "datagrip"],
        exe_path_contains: &["datagrip"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // CI/CD RUNNERS (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── GitHub Actions Runner ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["runner.listener", "runner.worker"],
        exe_path_contains: &["actions-runner"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Azure DevOps Agent ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["agent.listener", "agent.worker"],
        exe_path_contains: &["azure", "vsts-agent"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Buildkite Agent ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["buildkite-agent"],
        exe_path_contains: &["buildkite"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // PROXY SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── mitmproxy ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["mitmproxy", "mitmdump", "mitmweb"],
        exe_path_contains: &["mitmproxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["mitmproxy"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["mitmproxy"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080, 8081], version_from_header_prefix: None,
    },

    // ── Privoxy ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["privoxy"],
        exe_path_contains: &["privoxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["privoxy"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["privoxy"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8118], version_from_header_prefix: None,
    },

    // ── Tor ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["tor"],
        exe_path_contains: &["tor"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9050, 9150], version_from_header_prefix: None,
    },

    // ── Dante SOCKS Proxy ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["danted", "sockd"],
        exe_path_contains: &["dante"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1080], version_from_header_prefix: None,
    },

    // ── 3proxy ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["3proxy"],
        exe_path_contains: &["3proxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3128, 1080], version_from_header_prefix: None,
    },

    // ── tinyproxy ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["tinyproxy"],
        exe_path_contains: &["tinyproxy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &["tinyproxy"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8888], version_from_header_prefix: Some("tinyproxy"),
    },

    // ── Stunnel (SSL Tunnel) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["stunnel", "stunnel4"],
        exe_path_contains: &["stunnel"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // BACKUP SOFTWARE
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Veeam ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["veeam", "veeamservice", "veeam.backup.service"],
        exe_path_contains: &["veeam"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["veeam"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9392, 9393], version_from_header_prefix: None,
    },

    // ── Restic ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["restic"],
        exe_path_contains: &["restic"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8000], version_from_header_prefix: None,
    },

    // ── Duplicati ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["duplicati", "duplicati.server"],
        exe_path_contains: &["duplicati"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["duplicati"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8200], version_from_header_prefix: None,
    },

    // ── BorgBackup ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["borg", "borgmatic"],
        exe_path_contains: &["borg"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Bacula ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["bacula-dir", "bacula-sd", "bacula-fd"],
        exe_path_contains: &["bacula"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["bacula"],
        default_ports: &[9101, 9102, 9103], version_from_header_prefix: None,
    },

    // ── Acronis ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["acronis", "aakore", "active_protection_service"],
        exe_path_contains: &["acronis"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9876], version_from_header_prefix: None,
    },

    // ── CrashPlan ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["crashplan", "crashplanservice"],
        exe_path_contains: &["crashplan"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4242, 4243], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // NETWORKING TOOLS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Wireshark / TShark ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["wireshark", "tshark", "dumpcap"],
        exe_path_contains: &["wireshark"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Npcap ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["npcap"],
        exe_path_contains: &["npcap"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── Nmap / Ncat ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["nmap", "ncat"],
        exe_path_contains: &["nmap"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // CONTAINER REGISTRIES & SECURITY
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Docker Registry ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["registry"],
        exe_path_contains: &["registry"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("docker-distribution-api-version", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5000], version_from_header_prefix: None,
    },

    // ── Trivy (Container Scanner) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["trivy"],
        exe_path_contains: &["trivy"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4954], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SERVICE MESH
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Linkerd Proxy ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["linkerd2-proxy", "linkerd"],
        exe_path_contains: &["linkerd"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("l5d-server-id", "")], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4191, 4143], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // API & GRAPHQL
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Hasura GraphQL Engine ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["graphql-engine", "hasura"],
        exe_path_contains: &["hasura"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["hasura"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ── Apollo Server ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &[],
        cmdline_contains: &["apollo"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["apollo"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4000], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SEARCH ENGINES (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Manticore Search ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["searchd"],
        exe_path_contains: &["manticore"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["manticore"],
        default_ports: &[9306, 9308, 9312], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DOCUMENT & KNOWLEDGE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Wiki.js ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["wikijs", "wiki.js"],
        cmdline_contains: &["wiki"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["wiki.js"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },

    // ── BookStack ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["bookstack"],
        cmdline_contains: &["bookstack"], cmdline_requires_process: &["php"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["bookstack"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },

    // ── Outline ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["outline"],
        cmdline_contains: &["outline"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["outline"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },

    // ── Mattermost ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["mattermost"],
        exe_path_contains: &["mattermost"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[("x-request-id", ""), ("x-version-id", "")], html_title_contains: &["mattermost"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8065], version_from_header_prefix: None,
    },

    // ── Rocket.Chat ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["rocket.chat"],
        cmdline_contains: &["rocket.chat"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["rocket.chat"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[3000], version_from_header_prefix: None,
    },

    // ── Matrix / Synapse ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &["synapse"],
        exe_path_contains: &["synapse"],
        cmdline_contains: &["synapse"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &["synapse"], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8008, 8448], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // FILE TRANSFER (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── rsync Daemon ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["rsync", "rsyncd"],
        exe_path_contains: &["rsync"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["@RSYNCD"], banner_contains: &["rsyncd"],
        default_ports: &[873], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // LOW-CODE / NO-CODE PLATFORMS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── n8n ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["n8n"],
        exe_path_contains: &["n8n"],
        cmdline_contains: &["n8n"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["n8n"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5678], version_from_header_prefix: None,
    },

    // ── Appsmith ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 20,
        process_names: &[],
        exe_path_contains: &["appsmith"],
        cmdline_contains: &["appsmith"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["appsmith"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // AUTH SERVERS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Authentik ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["authentik"],
        exe_path_contains: &["authentik"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["authentik"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9000, 9443], version_from_header_prefix: None,
    },

    // ── Authelia ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["authelia"],
        exe_path_contains: &["authelia"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["authelia"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9091], version_from_header_prefix: None,
    },

    // ── Dex (OIDC Provider) ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["dex"],
        exe_path_contains: &["dex"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["dex"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5556, 5558], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // ML & AI PLATFORMS
    // ═══════════════════════════════════════════════════════════════════════════

    // ── MLflow ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["mlflow"],
        exe_path_contains: &["mlflow"],
        cmdline_contains: &["mlflow"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["mlflow"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[5000], version_from_header_prefix: None,
    },

    // ── TensorBoard ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["tensorboard"],
        exe_path_contains: &["tensorboard"],
        cmdline_contains: &["tensorboard"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["tensorboard"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[6006], version_from_header_prefix: None,
    },

    // ── Label Studio ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["label-studio"],
        exe_path_contains: &["label-studio", "label_studio"],
        cmdline_contains: &["label-studio"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["label studio"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ── Ollama ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["ollama"],
        exe_path_contains: &["ollama"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["ollama"],
        default_ports: &[11434], version_from_header_prefix: None,
    },

    // ── LM Studio ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["lm-studio", "lm studio"],
        exe_path_contains: &["lm studio", "lmstudio"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[1234], version_from_header_prefix: None,
    },

    // ── LocalAI ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["local-ai", "localai"],
        exe_path_contains: &["localai", "local-ai"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8080], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // INFRASTRUCTURE & DEVOPS (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Rancher ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["rancher"],
        exe_path_contains: &["rancher"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["rancher"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },

    // ── PgPool-II ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["pgpool"],
        exe_path_contains: &["pgpool"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["pgpool"],
        default_ports: &[9999, 9898], version_from_header_prefix: None,
    },

    // ── MaxScale (MariaDB Proxy) ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["maxscale"],
        exe_path_contains: &["maxscale"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &["maxscale"],
        default_ports: &[4006, 4008], version_from_header_prefix: None,
    },

    // ── Vitess ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["vtgate", "vttablet", "vtctld"],
        exe_path_contains: &["vitess"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["vitess"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[15000, 15001, 15999], version_from_header_prefix: None,
    },

    // ── Rundeck ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["rundeck", "rundeckd"],
        exe_path_contains: &["rundeck"],
        cmdline_contains: &["rundeck"], cmdline_requires_process: &["java"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["rundeck"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4440], version_from_header_prefix: None,
    },

    // ── AWX / Ansible Tower ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["awx-manage"],
        exe_path_contains: &["awx"],
        cmdline_contains: &["awx"], cmdline_requires_process: &["python", "python3"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["awx", "ansible tower"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[80, 443], version_from_header_prefix: None,
    },

    // ── SaltStack ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["salt-master", "salt-minion", "salt-api"],
        exe_path_contains: &["salt"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[4505, 4506], version_from_header_prefix: None,
    },

    // ── Puppet ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["puppet", "puppetserver", "puppet-agent"],
        exe_path_contains: &["puppet"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[8140], version_from_header_prefix: None,
    },

    // ── Chef ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["chef-server", "chef-client", "erchef"],
        exe_path_contains: &["chef"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["chef"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[443], version_from_header_prefix: None,
    },

    // ── Terraform Enterprise ──
    TechFingerprint {
        kind: ServerKind::GenericTcp, priority: 10,
        process_names: &["terraform"],
        exe_path_contains: &["terraform"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[], version_from_header_prefix: None,
    },

    // ── HashiCorp Boundary ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["boundary"],
        exe_path_contains: &["boundary"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["boundary"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9200, 9201, 9202], version_from_header_prefix: None,
    },

    // ── HashiCorp Waypoint ──
    TechFingerprint {
        kind: ServerKind::CustomHttp, priority: 10,
        process_names: &["waypoint"],
        exe_path_contains: &["waypoint"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["waypoint"],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[9701, 9702], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // EMAIL (Additional)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── MailHog ──
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["mailhog"],
        exe_path_contains: &["mailhog"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["mailhog"],
        banner_starts_with: &["220 "], banner_contains: &["mailhog"],
        default_ports: &[1025, 8025], version_from_header_prefix: None,
    },

    // ── MailPit ──
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["mailpit"],
        exe_path_contains: &["mailpit"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["mailpit"],
        banner_starts_with: &["220 "], banner_contains: &["mailpit"],
        default_ports: &[1025, 8025], version_from_header_prefix: None,
    },

    // ── Haraka ──
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["haraka"],
        exe_path_contains: &["haraka"],
        cmdline_contains: &["haraka"], cmdline_requires_process: &["node"],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &["220 "], banner_contains: &["haraka"],
        default_ports: &[25, 587], version_from_header_prefix: None,
    },

    // ── Zimbra ──
    TechFingerprint {
        kind: ServerKind::SMTP, priority: 10,
        process_names: &["zmmailboxdmgr", "zmmtactl"],
        exe_path_contains: &["zimbra"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &["zimbra"],
        banner_starts_with: &["220 "], banner_contains: &["zimbra"],
        default_ports: &[25, 465, 587, 7071], version_from_header_prefix: None,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // DNS SERVERS (Additional — individual entries for granular detection)
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Unbound ──
    TechFingerprint {
        kind: ServerKind::DNS, priority: 8,
        process_names: &["unbound"],
        exe_path_contains: &["unbound"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[53], version_from_header_prefix: None,
    },

    // ── BIND9 ──
    TechFingerprint {
        kind: ServerKind::DNS, priority: 8,
        process_names: &["named"],
        exe_path_contains: &["bind", "named"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[53, 953], version_from_header_prefix: None,
    },

    // ── PowerDNS ──
    TechFingerprint {
        kind: ServerKind::DNS, priority: 8,
        process_names: &["pdns_server", "pdns_recursor"],
        exe_path_contains: &["powerdns", "pdns"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[53, 8081], version_from_header_prefix: None,
    },

    // ── DNSMasq ──
    TechFingerprint {
        kind: ServerKind::DNS, priority: 8,
        process_names: &["dnsmasq"],
        exe_path_contains: &["dnsmasq"],
        cmdline_contains: &[], cmdline_requires_process: &[],
        http_server_contains: &[], http_powered_by_contains: &[],
        http_header_contains: &[], html_title_contains: &[],
        banner_starts_with: &[], banner_contains: &[],
        default_ports: &[53], version_from_header_prefix: None,
    },
];

/// Total number of fingerprints in the database.
pub const FINGERPRINT_COUNT: usize = FINGERPRINTS.len();
