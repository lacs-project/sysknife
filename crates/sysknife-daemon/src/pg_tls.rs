//! TLS floor for Postgres connections.
//!
//! sqlx defaults to `sslmode=Prefer`, which silently downgrades to a plaintext
//! connection if the server answers the SSL negotiation with `N`. For an audit
//! store that carries a database credential, that is a downgrade-to-cleartext
//! vector: an active network attacker who can strip the `S` response reads the
//! credential (#149).
//!
//! `sslmode=require` is NOT sufficient: sqlx (`connection/tls.rs`) sets
//! `accept_invalid_certs = true` for `require`, so the client completes a TLS
//! handshake with any certificate — including a throwaway self-signed one an
//! active MITM mints on the fly — and then sends the credential over what it
//! believes is a secure channel. Only `verify-ca` (validates the certificate
//! chain) and `verify-full` (also checks the hostname) authenticate the server.
//! We therefore require at least `verify-ca` for any connection that crosses the
//! network, and recommend `verify-full`.
//!
//! Connections that never touch the network — unix-domain sockets and loopback
//! addresses — are exempt, so local development and the packaged local database
//! keep working without ceremony.

use std::net::Ipv4Addr;

use sqlx_postgres::{PgConnectOptions, PgSslMode};

/// Refuse a Postgres connection whose effective `sslmode` would let the
/// credential be read by a network attacker (plaintext downgrade, or an
/// unauthenticated TLS handshake against an attacker-supplied certificate).
///
/// Returns `Err(message)` with an actionable remediation for a remote TCP
/// connection below `sslmode=verify-ca`; `Ok(())` for unix sockets, loopback
/// hosts, and any `verify-ca`/`verify-full` connection.
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
        PgSslMode::VerifyCa | PgSslMode::VerifyFull => Ok(()),
        insecure => Err(format!(
            "refusing a Postgres connection to {host:?} with sslmode={insecure:?}: it does not \
             authenticate the server (disable/allow/prefer can downgrade to plaintext; require \
             completes TLS against any certificate, so an active man-in-the-middle can present a \
             self-signed cert and read the database credential). Add ?sslmode=verify-full \
             (recommended) or at least ?sslmode=verify-ca to the URL."
        )),
    }
}

/// A host that resolves to the local machine and so never crosses a network the
/// attacker in the threat model can observe.
///
/// This trusts the literal hostname *string*, not a resolved address: an
/// attacker who controls local name resolution (a tampered `/etc/hosts` or
/// resolver) could point `localhost` off-box and still be exempted. That is a
/// strictly stronger attacker than the network MITM this floor defends against,
/// so the string check is acceptable here.
///
/// `PgConnectOptions::from_str` (the only way `opts` is built in this crate)
/// returns IPv4 literals unbracketed and IPv6 literals bracket-wrapped (e.g.
/// `[::1]`), which is why the IPv6 case is a string match, not an `Ipv6Addr`
/// parse (the brackets make `Ipv6Addr::from_str` fail). The host is normalized
/// for case and a trailing dot so `LOCALHOST.` is still recognized.
fn is_loopback(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost" || normalized == "[::1]" {
        return true;
    }
    // IPv4 literal loopback (127.0.0.0/8), returned unbracketed by from_str.
    host.parse::<Ipv4Addr>()
        .map(|v4| v4.is_loopback())
        .unwrap_or(false)
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
    fn a_remote_tcp_url_with_sslmode_allow_is_refused() {
        // allow tries plaintext first, the mirror of prefer.
        require_tls_for_remote(&opts("postgres://u:p@db.example.com/audit?sslmode=allow"))
            .expect_err("allow (plaintext-first) must be refused");
    }

    #[test]
    fn a_remote_tcp_url_with_sslmode_require_is_refused() {
        // require encrypts but accepts any certificate, so an active MITM still
        // reads the credential. It is below the floor.
        require_tls_for_remote(&opts("postgres://u:p@db.example.com/audit?sslmode=require"))
            .expect_err("require does not authenticate the server and must be refused");
    }

    #[test]
    fn a_remote_tcp_url_with_verify_ca_is_allowed() {
        require_tls_for_remote(&opts(
            "postgres://u:p@db.example.com/audit?sslmode=verify-ca",
        ))
        .expect("verify-ca authenticates the cert chain and is the floor");
    }

    #[test]
    fn a_remote_tcp_url_with_verify_full_is_allowed() {
        require_tls_for_remote(&opts(
            "postgres://u:p@db.example.com/audit?sslmode=verify-full",
        ))
        .expect("verify-full must be allowed");
    }

    #[test]
    fn a_remote_host_built_without_a_url_is_refused() {
        // Cover the builder path (get_ssl_mode on a non-from_str construction).
        let o = PgConnectOptions::new()
            .host("db.example.com")
            .username("u")
            .database("audit")
            .ssl_mode(PgSslMode::Disable);
        require_tls_for_remote(&o).expect_err("a builder-constructed remote host must be refused");
    }

    #[test]
    fn a_loopback_host_without_sslmode_is_allowed() {
        require_tls_for_remote(&opts("postgres://u:p@localhost:5432/audit"))
            .expect("localhost never crosses the network");
        require_tls_for_remote(&opts("postgres://u:p@127.0.0.1:5432/audit"))
            .expect("127.0.0.1 is loopback");
    }

    #[test]
    fn an_ipv6_loopback_url_is_allowed() {
        // from_str returns get_host() == "[::1]" for a bracketed IPv6 literal;
        // this pins the exact string is_loopback must recognize.
        require_tls_for_remote(&opts("postgres://u:p@[::1]:5432/audit"))
            .expect("[::1] is IPv6 loopback and never crosses the network");
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
