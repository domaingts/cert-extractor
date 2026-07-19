use std::net::IpAddr;

use rustls::pki_types::ServerName;

use crate::error::ApiError;

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub server_name: ServerName<'static>,
}

impl Endpoint {
    pub fn parse(hostname: &str, port: u16) -> Result<Self, ApiError> {
        let mut host = hostname.trim();
        if host.is_empty() {
            return Err(ApiError::invalid(
                "invalid_hostname",
                "backend.error.hostnameRequired",
            ));
        }
        if port == 0 {
            return Err(ApiError::invalid(
                "invalid_port",
                "backend.error.invalidPort",
            ));
        }
        if host.contains("://")
            || host.contains('/')
            || host.contains('?')
            || host.contains('#')
            || host.contains('@')
        {
            return Err(ApiError::invalid(
                "invalid_hostname",
                "backend.error.hostnameUrlNotAllowed",
            ));
        }

        if host.starts_with('[') || host.ends_with(']') {
            if !(host.starts_with('[') && host.ends_with(']')) {
                return Err(ApiError::invalid(
                    "invalid_hostname",
                    "backend.error.invalidIpv6Brackets",
                ));
            }
            host = &host[1..host.len() - 1];
        }

        let (normalized, server_name) = if let Ok(ip) = host.parse::<IpAddr>() {
            (ip.to_string(), ServerName::IpAddress(ip.into()))
        } else {
            if host.contains(':') {
                return Err(ApiError::invalid(
                    "invalid_hostname",
                    "backend.error.embeddedPort",
                ));
            }
            let without_dot = host.strip_suffix('.').unwrap_or(host);
            let ascii = idna::domain_to_ascii(without_dot).map_err(|_| {
                ApiError::invalid("invalid_hostname", "backend.error.invalidDnsName")
            })?;
            let normalized = ascii.to_ascii_lowercase();
            let server_name = ServerName::try_from(normalized.clone()).map_err(|_| {
                ApiError::invalid("invalid_hostname", "backend.error.invalidDnsName")
            })?;
            (normalized, server_name)
        };

        Ok(Self {
            host: normalized,
            port,
            server_name,
        })
    }

    pub fn display(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoint;

    #[test]
    fn normalizes_dns_names() {
        let endpoint = Endpoint::parse(" Example.COM. ", 443).unwrap();
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.display(), "example.com:443");
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        let endpoint = Endpoint::parse("[::1]", 8443).unwrap();
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.display(), "[::1]:8443");
    }

    #[test]
    fn rejects_urls_and_embedded_ports() {
        let url_error = Endpoint::parse("https://example.com", 443).unwrap_err();
        assert_eq!(url_error.message.key, "backend.error.hostnameUrlNotAllowed");

        let port_error = Endpoint::parse("example.com:443", 443).unwrap_err();
        assert_eq!(port_error.message.key, "backend.error.embeddedPort");
    }
}
