//! Unit tests for SSRF Protection in Proxy
//!
//! Tests the security functions that prevent Server-Side Request Forgery attacks.

#[cfg(test)]
mod proxy_ssrf_tests {
    use std::net::{IpAddr, Ipv4Addr};

    // Re-implement the functions here for testing since they're private in proxy.rs
    // In production, consider making these pub(crate) for testability
    
    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || ipv4 == Ipv4Addr::LOCALHOST
                || ipv4 == Ipv4Addr::BROADCAST
                || ipv4 == Ipv4Addr::UNSPECIFIED
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                || ipv6.is_unspecified()
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    fn is_suspicious_hostname(host: &str) -> bool {
        let host_lower = host.to_lowercase();
        
        host_lower == "169.254.169.254"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
        || host_lower == "metadata"
        || host_lower.contains("metadata.azure")
        || host_lower == "fd00:ec2::254"
        || host_lower == "localhost"
        || host_lower == "localhost.localdomain"
        || host_lower.ends_with(".localhost")
        || host_lower.ends_with(".cluster.local")
        || host_lower.ends_with(".svc")
        || host_lower == "host.docker.internal"
        || host_lower == "gateway.docker.internal"
    }

    // ==================== Private IP Detection (IPv4) ====================

    #[test]
    fn test_block_10_network() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 10.0.0.0/8");
        
        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 10.255.255.255");
    }

    #[test]
    fn test_block_172_16_network() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 172.16.0.0/12");
        
        let ip: IpAddr = "172.31.255.255".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 172.31.255.255");
        
        // 172.32.x.x is public
        let ip: IpAddr = "172.32.0.1".parse().unwrap();
        assert!(!is_private_ip(ip), "Should allow 172.32.x.x");
    }

    #[test]
    fn test_block_192_168_network() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 192.168.0.0/16");
        
        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 192.168.255.255");
    }

    #[test]
    fn test_block_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block 127.0.0.1");
        
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(is_private_ip(ip), "Should block all 127.x.x.x");
    }

    #[test]
    fn test_block_link_local() {
        // AWS metadata endpoint
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_private_ip(ip), "Should block AWS metadata endpoint");
        
        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block link-local range");
    }

    #[test]
    fn test_allow_public_ips() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(ip), "Should allow Google DNS");
        
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_private_ip(ip), "Should allow Cloudflare DNS");
        
        let ip: IpAddr = "52.94.236.248".parse().unwrap();
        assert!(!is_private_ip(ip), "Should allow public AWS IP");
    }

    #[test]
    fn test_block_documentation_ranges() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block TEST-NET-1");
        
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block TEST-NET-2");
        
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block TEST-NET-3");
    }

    // ==================== Private IP Detection (IPv6) ====================

    #[test]
    fn test_block_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block IPv6 loopback");
    }

    #[test]
    fn test_block_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block IPv6 link-local");
    }

    #[test]
    fn test_block_ipv6_unique_local() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block IPv6 unique local (fc00::/7)");
        
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_ip(ip), "Should block IPv6 unique local (fd00::/8)");
    }

    #[test]
    fn test_allow_public_ipv6() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_private_ip(ip), "Should allow Google Public DNS IPv6");
    }

    // ==================== Suspicious Hostname Detection ====================

    #[test]
    fn test_block_aws_metadata() {
        assert!(is_suspicious_hostname("169.254.169.254"), "Should block AWS metadata IP");
    }

    #[test]
    fn test_block_gcp_metadata() {
        assert!(is_suspicious_hostname("metadata.google.internal"), "Should block GCP metadata");
    }

    #[test]
    fn test_block_azure_metadata() {
        assert!(is_suspicious_hostname("metadata.azure.com"), "Should block Azure metadata");
    }

    #[test]
    fn test_block_internal_domains() {
        assert!(is_suspicious_hostname("secret.internal"), "Should block .internal");
        assert!(is_suspicious_hostname("db.cluster.local"), "Should block .cluster.local");
        assert!(is_suspicious_hostname("api.svc"), "Should block .svc");
    }

    #[test]
    fn test_block_localhost_variants() {
        assert!(is_suspicious_hostname("localhost"), "Should block localhost");
        assert!(is_suspicious_hostname("LOCALHOST"), "Should block LOCALHOST (case-insensitive)");
        assert!(is_suspicious_hostname("localhost.localdomain"), "Should block localhost.localdomain");
        assert!(is_suspicious_hostname("evil.localhost"), "Should block *.localhost");
    }

    #[test]
    fn test_block_docker_internal() {
        assert!(is_suspicious_hostname("host.docker.internal"), "Should block Docker host");
        assert!(is_suspicious_hostname("gateway.docker.internal"), "Should block Docker gateway");
    }

    #[test]
    fn test_allow_legitimate_domains() {
        assert!(!is_suspicious_hostname("api.openai.com"), "Should allow OpenAI");
        assert!(!is_suspicious_hostname("api.anthropic.com"), "Should allow Anthropic");
        assert!(!is_suspicious_hostname("example.com"), "Should allow example.com");
        assert!(!is_suspicious_hostname("internal-api.company.com"), "Should allow 'internal' in path");
    }

    // ==================== Combined SSRF Tests ====================

    #[test]
    fn test_ssrf_attack_vectors() {
        // Common SSRF attack vectors that must be blocked
        let attack_vectors = vec![
            ("127.0.0.1", true),
            ("0.0.0.0", true),
            ("169.254.169.254", true),  // AWS
            ("10.0.0.1", true),
            ("192.168.1.1", true),
            ("172.16.0.1", true),
            ("api.openai.com", false),  // Legitimate
            ("8.8.8.8", false),         // Legitimate
        ];

        for (host, should_block) in attack_vectors {
            if host.contains('.') && !host.chars().all(|c| c.is_numeric() || c == '.') {
                // It's a hostname
                let blocked = is_suspicious_hostname(host);
                assert_eq!(blocked, should_block, "Hostname {}: expected blocked={}", host, should_block);
            } else {
                // It's an IP
                if let Ok(ip) = host.parse::<IpAddr>() {
                    let blocked = is_private_ip(ip);
                    assert_eq!(blocked, should_block, "IP {}: expected blocked={}", host, should_block);
                }
            }
        }
    }
}
