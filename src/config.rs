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

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "opensmtpd-filter-skimverify")]
#[command(about = "OpenSMTPD filter for DKIM verification and SPF alignment")]
pub struct Config {
    /// Hostname to use in Authentication-Results header
    #[arg(short = 'H', long, default_value = "localhost")]
    pub hostname: String,

    /// Reject messages that fail DKIM verification
    #[arg(short, long, default_value_t = false)]
    pub reject_on_fail: bool,

    /// Custom rejection message
    #[arg(long, default_value = "550 5.7.1 DKIM verification failed")]
    pub reject_message: String,

    /// Log level [trace, debug, info, warn, error]
    #[arg(short, long, default_value = "info")]
    pub log_level: tracing::Level,
}
