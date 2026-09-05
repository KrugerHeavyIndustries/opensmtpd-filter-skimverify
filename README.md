# filter-skimverify

   "skim" (a portmanteau of "spf" and "dkim")

Yes, it is cheesy but it does the job.

An OpenSMTPD filter that verifies DKIM signatures, performs SPF checks, and validates DKIM domain alignment on incoming messages. It inserts an `Authentication-Results` header with the verification outcomes and can optionally reject messages that fail authentication.

## How it works

The filter integrates with OpenSMTPD's filter protocol to intercept incoming mail at the data phase:

1. Collects message lines as they arrive from OpenSMTPD
2. When the message is complete (signalled by `.`), performs DKIM signature verification using DNS lookups
3. Performs SPF verification by querying the sender domain's SPF DNS record and validating the source IP is authorized
4. Checks DKIM domain alignment by comparing the DKIM signing domain against the envelope sender domain (relaxed alignment — organizational domain match is sufficient)
5. Inserts an `Authentication-Results` header at the top of the message body
6. If `--reject-on-fail` is enabled, rejects messages at the commit phase when any check fails (DKIM, SPF, or alignment)

## Building

Requires Rust 1.56+ (edition 2021).

```sh
cargo build --release
```

The binary will be at `target/release/filter-skimverify`.

## Usage

```
filter-skimverify [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-H`, `--hostname <HOST>` | Hostname for the Authentication-Results header | `localhost` |
| `-r`, `--reject-on-fail` | Reject messages that fail DKIM/SPF checks | disabled |
| `--reject-message <MSG>` | Custom rejection message | `550 5.7.1 DKIM verification failed` |

### OpenSMTPD configuration

Add the filter to your `smtpd.conf`:

```
filter skimverify proc-exec "/usr/local/libexec/filter-skimverify -H mail.example.com"

listen on all filter skimverify
```

To reject unauthenticated mail:

```
filter skimverify proc-exec "/usr/local/libexec/filter-skimverify -H mail.example.com --reject-on-fail"
```

### Logging

Logs are written to stderr at `info` level by default. Control verbosity with the --log-level command line argument:

```
filter skimverify proc-exec "/usr/local/libexec/filter-skimverify -H mail.example.com --log-level debug"
```

## Example output

A passing message will have a header inserted like:

```
Authentication-Results: mail.example.com; dkim=pass header.d=example.com header.s=sel1; spf=pass smtp.mailfrom=user@example.com
```

A failing message:

```
Authentication-Results: mail.example.com; dkim=fail (body hash did not verify) header.d=spoofed.com; spf=fail smtp.mailfrom=attacker@evil.com
```

The header format is compliant with [RFC 7601](https://www.rfc-editor.org/rfc/rfc7601).

## License

ISC
