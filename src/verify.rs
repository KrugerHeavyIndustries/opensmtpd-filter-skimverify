/*
 * Copyright (c) 2026 Chris Kruger <montdidier@users.noreply.github.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::net::IpAddr;

use mail_auth::common::verify::VerifySignature;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, DkimResult, SpfResult, MessageAuthenticator};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub dkim: DkimStatus,
    pub spf: SpfStatus,
    pub alignment_pass: bool,
}

#[derive(Debug, Clone)]
pub struct DkimStatus {
    pub result: &'static str,
    pub domain: Option<String>,
    pub selector: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SpfStatus {
    pub result: &'static str,
    pub smtp_mailfrom: Option<String>,
    pub smtp_helo: Option<String>,
}

pub async fn verify_message(
    authenticator: &MessageAuthenticator,
    raw_message: &[u8],
    mail_from: Option<&str>,
    helo_domain: Option<&str>,
    source_ip: Option<&str>,
) -> VerificationResult {
    let dkim_result = verify_dkim(authenticator, raw_message).await;
    let spf_result = verify_spf(authenticator, source_ip, helo_domain, mail_from).await;
    let alignment_pass = check_dkim_alignment(&dkim_result, mail_from);

    VerificationResult {
        dkim: DkimStatus {
            result: dkim_result.result,
            domain: dkim_result.domain,
            selector: dkim_result.selector,
            comment: dkim_result.comment,
        },
        spf: SpfStatus {
            result: spf_result.result,
            smtp_mailfrom: spf_result.smtp_mailfrom,
            smtp_helo: spf_result.smtp_helo,
        },
        alignment_pass,
    }
}

struct DkimVerifyResult {
    result: &'static str,
    domain: Option<String>,
    selector: Option<String>,
    comment: Option<String>,
}

struct SpfVerifyResult {
    result: &'static str,
    smtp_mailfrom: Option<String>,
    smtp_helo: Option<String>,
}

async fn verify_dkim(authenticator: &MessageAuthenticator, raw_message: &[u8]) -> DkimVerifyResult {
    let authenticated_message = match AuthenticatedMessage::parse(raw_message) {
        Some(msg) => msg,
        None => {
            return DkimVerifyResult {
                result: "none",
                domain: None,
                selector: None,
                comment: Some("message parse failure".to_string()),
            };
        }
    };

    let dkim_output = authenticator.verify_dkim(&authenticated_message).await;

    if dkim_output.is_empty() {
        return DkimVerifyResult {
            result: "none",
            domain: None,
            selector: None,
            comment: Some("no signature".to_string()),
        };
    }

    for output in dkim_output.iter() {
        let domain = output.signature().map(|s| s.domain().to_string());
        let selector = output.signature().map(|s| s.selector().to_string());
        match output.result() {
            DkimResult::Pass => {
                return DkimVerifyResult {
                    result: "pass",
                    domain,
                    selector,
                    comment: None,
                };
            }
            DkimResult::Fail(err) => {
                return DkimVerifyResult {
                    result: "fail",
                    domain,
                    selector,
                    comment: Some(err.to_string()),
                };
            }
            _ => continue,
        }
    }

    DkimVerifyResult {
        result: "none",
        domain: None,
        selector: None,
        comment: Some("no valid signature found".to_string()),
    }
}

async fn verify_spf(
    authenticator: &MessageAuthenticator,
    source_ip: Option<&str>,
    helo_domain: Option<&str>,
    mail_from: Option<&str>,
) -> SpfVerifyResult {
    let ip: IpAddr = match source_ip.and_then(|s| s.parse().ok()) {
        Some(ip) => ip,
        None => {
            return SpfVerifyResult {
                result: "none",
                smtp_mailfrom: mail_from.map(|s| s.to_string()),
                smtp_helo: helo_domain.map(|s| s.to_string()),
            };
        }
    };

    let helo = helo_domain.unwrap_or("unknown");
    let default_sender = format!("postmaster@{}", helo);
    let sender = mail_from.unwrap_or(&default_sender);

    let output = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            ip,
            helo,
            helo,
            sender
        )).await;

    let result = match output.result() {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    };

    SpfVerifyResult {
        result,
        smtp_mailfrom: mail_from.map(|s| s.to_string()),
        smtp_helo: Some(helo.to_string()),
    }
}

fn check_dkim_alignment(dkim_result: &DkimVerifyResult, mail_from: Option<&str>) -> bool {
    let mail_from_domain = match mail_from {
        Some(addr) => match addr.rfind('@') {
            Some(at_pos) => addr[at_pos + 1..].to_lowercase(),
            None => return false,
        },
        None => return false,
    };

    let dkim_domain = match &dkim_result.domain {
        Some(d) => d.to_lowercase(),
        None => return false,
    };

    domains_align(&mail_from_domain, &dkim_domain)
}

fn domains_align(domain_a: &str, domain_b: &str) -> bool {
    if domain_a == domain_b {
        return true;
    }
    let org_a = organizational_domain(domain_a);
    let org_b = organizational_domain(domain_b);
    org_a == org_b
}

fn organizational_domain(domain: &str) -> &str {
    let last_dot = match domain.rfind('.') {
        Some(pos) => pos,
        None => return domain,
    };
    let second_last = domain[..last_dot].rfind('.').map(|p| p + 1).unwrap_or(0);
    &domain[second_last..]
}

pub fn format_auth_results(hostname: &str, result: &VerificationResult) -> String {
    let mut parts = Vec::new();

    // dkim method
    let mut dkim_part = format!("dkim={}", result.dkim.result);
    if let Some(comment) = &result.dkim.comment {
        dkim_part.push_str(&format!(" ({})", comment));
    }
    if let Some(domain) = &result.dkim.domain {
        dkim_part.push_str(&format!(" header.d={}", domain));
    }
    if let Some(selector) = &result.dkim.selector {
        dkim_part.push_str(&format!(" header.s={}", selector));
    }
    parts.push(dkim_part);

    // spf method
    let mut spf_part = format!("spf={}", result.spf.result);
    if let Some(mailfrom) = &result.spf.smtp_mailfrom {
        spf_part.push_str(&format!(" smtp.mailfrom={}", mailfrom));
    } else if let Some(helo) = &result.spf.smtp_helo {
        spf_part.push_str(&format!(" smtp.helo={}", helo));
    }
    parts.push(spf_part);

    format!("Authentication-Results: {}; {}", hostname, parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domains_align_exact() {
        assert!(domains_align("example.com", "example.com"));
    }

    #[test]
    fn test_domains_align_subdomain() {
        assert!(domains_align("mail.example.com", "example.com"));
        assert!(domains_align("example.com", "sub.example.com"));
    }

    #[test]
    fn test_domains_no_align() {
        assert!(!domains_align("example.com", "other.com"));
        assert!(!domains_align("evil-example.com", "example.com"));
    }

    #[test]
    fn test_organizational_domain() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.example.com"), "example.com");
    }

    #[test]
    fn test_format_auth_results_pass() {
        let result = VerificationResult {
            dkim: DkimStatus {
                result: "pass",
                domain: Some("example.com".to_string()),
                selector: Some("sel1".to_string()),
                comment: None,
            },
            spf: SpfStatus {
                result: "pass",
                smtp_mailfrom: Some("user@example.com".to_string()),
                smtp_helo: Some("mail.example.com".to_string()),
            },
            alignment_pass: true,
        };
        let header = format_auth_results("mx.example.com", &result);
        assert_eq!(
            header,
            "Authentication-Results: mx.example.com; dkim=pass header.d=example.com header.s=sel1; spf=pass smtp.mailfrom=user@example.com"
        );
    }

    #[test]
    fn test_format_auth_results_fail() {
        let result = VerificationResult {
            dkim: DkimStatus {
                result: "fail",
                domain: Some("spoofed.com".to_string()),
                selector: None,
                comment: Some("body hash did not verify".to_string()),
            },
            spf: SpfStatus {
                result: "none",
                smtp_mailfrom: None,
                smtp_helo: Some("unknown".to_string()),
            },
            alignment_pass: false,
        };
        let header = format_auth_results("mx.example.com", &result);
        assert_eq!(
            header,
            "Authentication-Results: mx.example.com; dkim=fail (body hash did not verify) header.d=spoofed.com; spf=none smtp.helo=unknown"
        );
    }
}
