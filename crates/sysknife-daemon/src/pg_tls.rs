//! TLS floor for Postgres connections.
//!
//! sqlx defaults to `sslmode=Prefer`, which silently downgrades to a plaintext
//! connection if the server answers the SSL negotiation with `N`. For an audit
//! store that carries a database credential, that is a downgrade-to-cleartext
//! vector: an active network attacker who can strip the `S` response reads the
//! credential (#149). We therefore require at least `sslmode=require` for any
//! connection that crosses the network, and recommend `verify-full`.
//!
//! Connections that never touch the network — unix-domain sockets and loopback
//! addresses — are exempt, so local development and the packaged local database
//! keep working without ceremony.

use std::net::{Ipv4Addr, Ipv6Addr};

use sqlx_postgres::{PgConnectOptions, PgSslMode};

/// Refuse a Postgres connection whose effective `sslmode` would allow the
/// credential to travel in cleartext across the network.
///
/// Returns `Err(message)` with an actionable remediation for a remote TCP
/// connection below `sslmode=require`; `Ok(())` for unix sockets, loopback
/// hosts, and any `require`/`verify-ca`/`verify-full` connection.
pub(crate) fn require_tls_for_remote(opts: &PgConnectOptions) -> Result<(), String> {
    // A unix-domain socket never leaves the host.
    if opts.get_socket().is_some() {
        return Ok(());
    }
    let host = opts.get_host();
    if is_loopback(host) {
        return Ok(());
    }
    match opts.get_ssl_mode() {
        PgSslMode::Require | PgSslMode::VerifyCa | PgSslMode::VerifyFull => Ok(()),
        insecure => Err(format!(
            "refusing a Postgres connection to {host:?} with sslmode={insecure:?}: it can \
             silently downgrade to plaintext and leak the database credential to a network \
             attacker. Add ?sslmode=verify-full (recommended, also authenticates the server) \
             or at least ?sslmode=require to the URL."
        )),
    }
}

/// A host that resolves to the local machine and so never crosses a network the
/// attacker in the threat model can observe. Literal loopback addresses and the
/// conventional `localhost` name qualify.
fn is_loopback(host: &str) -> bool {
    if host == "localhost" || host == "::1" || host == "[::1]" {
        return true;
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn opts(url: &str) -> PgConnectOptions {
        PgConnectOptions::from_str(url).expect("valid test URL")
    }

    #[test]
    fn a_remote_tcp_url_without_sslmode_is_refused() {
        let err = require_tls_for_remote(&opts("postgres://u:p@db.example.com:5432/audit"))
            .expect_err("Prefer default must be refused for a remote host");
        assert!(
            err.contains("sslmode"),
            "message should name sslmode: {err}"
        );
        assert!(
            err.contains("db.example.com"),
            "message should name the host: {err}"
        );
    }

    #[test]
    fn a_remote_tcp_url_with_sslmode_disable_is_refused() {
        require_tls_for_remote(&opts("postgres://u:p@db.example.com/audit?sslmode=disable"))
            .expect_err("disable must be refused");
    }

    #[test]
    fn a_remote_tcp_url_with_sslmode_prefer_is_refused() {
        require_tls_for_remote(&opts("postgres://u:p@db.example.com/audit?sslmode=prefer"))
            .expect_err("prefer (downgradeable) must be refused");
    }

    #[test]
    fn a_remote_tcp_url_with_sslmode_require_is_allowed() {
        require_tls_for_remote(&opts("postgres://u:p@db.example.com/audit?sslmode=require"))
            .expect("require is the floor and must be allowed");
    }

    #[test]
    fn a_remote_tcp_url_with_verify_full_is_allowed() {
        require_tls_for_remote(&opts(
            "postgres://u:p@db.example.com/audit?sslmode=verify-full",
        ))
        .expect("verify-full must be allowed");
    }

    #[test]
    fn a_loopback_host_without_sslmode_is_allowed() {
        require_tls_for_remote(&opts("postgres://u:p@localhost:5432/audit"))
            .expect("localhost never crosses the network");
        require_tls_for_remote(&opts("postgres://u:p@127.0.0.1:5432/audit"))
            .expect("127.0.0.1 is loopback");
    }

    #[test]
    fn a_unix_socket_without_sslmode_is_allowed() {
        // A unix-domain socket carries no TLS and needs none — it never leaves
        // the host. Build it directly (the URL socket forms are finicky).
        let o = PgConnectOptions::new()
            .socket("/var/run/postgresql")
            .username("u")
            .database("audit");
        assert!(o.get_socket().is_some(), "should be a unix socket");
        require_tls_for_remote(&o).expect("unix socket never crosses the network");
    }

    #[test]
    fn a_non_loopback_ip_without_sslmode_is_refused() {
        require_tls_for_remote(&opts("postgres://u:p@10.0.0.5:5432/audit"))
            .expect_err("a private-range remote IP is still on the network");
    }
}
