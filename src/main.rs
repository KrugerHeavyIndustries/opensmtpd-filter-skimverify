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

mod config;
mod verify;

use clap::Parser;
use config::Config;
use mail_auth::MessageAuthenticator;
use opensmtpd_filter::{Address, Direction, Filter, FilterResponse, Session, SmtpFilterRunner};
use std::collections::HashMap;
use std::io;
use std::process::ExitCode;
use tracing::{info, warn};
use verify::{format_auth_results, verify_message, VerificationResult};

struct DkimVerifyFilter {
    config: Config,
    authenticator: MessageAuthenticator,
    rt: tokio::runtime::Runtime,
    message_lines: HashMap<u64, Vec<String>>,
    pending_results: HashMap<u64, VerificationResult>,
}

impl DkimVerifyFilter {
    fn source_ip(session: &Session) -> Option<String> {
        session.src.as_ref().and_then(|a| match a {
            Address::Ip(addr) => Some(addr.ip().to_string()),
            Address::Unix(_) => None,
        })
    }
}

impl Filter for DkimVerifyFilter {
    fn on_filter_data_line(&mut self, session: &Session, line: &str) -> Vec<String> {
        let reqid = session.reqid;

        if line != "." {
            self.message_lines
                .entry(reqid)
                .or_default()
                .push(line.to_string());
            return vec![];
        }

        let lines = self.message_lines.remove(&reqid).unwrap_or_default();
        let raw_message = build_raw_message(&lines);

        let mail_from = session.mailfrom.as_deref();
        let helo_domain = session.identity.as_deref();
        let source_ip = Self::source_ip(session);

        let result = self.rt.block_on(verify_message(
            &self.authenticator,
            &raw_message,
            mail_from,
            helo_domain,
            source_ip.as_deref(),
        ));

        let auth_header = format_auth_results(&self.config.hostname, &result);
        info!(
            reqid = format_args!("{:016x}", reqid),
            dkim = result.dkim.result,
            spf = result.spf.result,
            aligned = result.alignment_pass,
            "verification complete"
        );

        if self.config.reject_on_fail {
            self.pending_results.insert(reqid, result);
        }

        let mut output = Vec::with_capacity(lines.len() + 2);
        let mut in_headers = true;
        let mut header_inserted = false;

        for msg_line in &lines {
            if in_headers && msg_line.is_empty() {
                if !header_inserted {
                    output.push(auth_header.clone());
                    header_inserted = true;
                }
                in_headers = false;
            }
            output.push(msg_line.clone());
        }

        output.push(".".to_string());
        output
    }

    fn on_filter_commit(&mut self, session: &Session) -> FilterResponse {
        if let Some(result) = self.pending_results.remove(&session.reqid) {
            let dkim_pass = result.dkim.result == "pass";
            let spf_pass = result.spf.result == "pass";
            if !dkim_pass || !spf_pass || !result.alignment_pass {
                warn!(
                    reqid = format_args!("{:016x}", session.reqid),
                    dkim_domain = ?result.dkim.domain,
                    "rejecting message: authentication failed"
                );
                return FilterResponse::Reject {
                    code: 550,
                    message: self.config.reject_message.clone(),
                };
            }
        }
        FilterResponse::Proceed
    }

    fn on_report_link_disconnect(&mut self, session: &Session, _direction: Direction) {
        self.message_lines.remove(&session.reqid);
        self.pending_results.remove(&session.reqid);
    }
}

fn main() -> ExitCode {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(io::stderr)
        .init();

    info!(
        "starting filter, hostname={}, reject_on_fail={}",
        config.hostname, config.reject_on_fail
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let authenticator = rt.block_on(async { MessageAuthenticator::new_system_conf() })
                          .expect("failed to create mail_auth::Authenticator");

    let reject_on_fail = config.reject_on_fail;

    let filter = DkimVerifyFilter {
        config,
        authenticator,
        rt,
        message_lines: HashMap::new(),
        pending_results: HashMap::new(),
    };

    let mut runner = SmtpFilterRunner::new(filter);
    runner
        .register_filter_data_line()
        .register_report_tx_mail(Direction::Incoming)
        .register_report_identify(Direction::Incoming)
        .register_report_connect(Direction::Incoming);

    if reject_on_fail {
        runner.register_filter_commit();
    }

    runner.run()
}

fn build_raw_message(lines: &[String]) -> Vec<u8> {
    let mut raw = Vec::new();
    for line in lines {
        raw.extend_from_slice(line.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw
}
