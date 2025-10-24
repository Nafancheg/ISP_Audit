# ISP_Audit

Single-file, self-contained Windows .NET tool to run quick ISP diagnostics for DNS filtering/bogus answers, TCP port reachability, UDP/QUIC availability (UDP DNS probe), HTTPS/TLS behavior, traceroute wrapper, and RST-injection heuristic. Produces human-readable console output and a structured JSON `report.json`.

## Build

Requires .NET 9 SDK.

- Debug build: `dotnet build -c Debug`
- Single-file publish: `dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish`

GitHub Actions workflow is included at `.github/workflows/build.yml` and uploads `ISP_Audit.exe` as an artifact.

## Usage

Examples:

- Default targets and save report:
  `ISP_Audit.exe --report isp_report.json`

- Explicit targets and short JSON to stdout:
  `ISP_Audit.exe --targets youtube.com,discord.com --json --report result.json`

- Disable traceroute and increase timeouts:
  `ISP_Audit.exe --no-trace --timeout 12 --verbose`

Options:

- `--targets <file|list>` Comma-separated hosts or path to JSON/CSV
- `--report <path>` Save JSON report (default `isp_report.json`)
- `--timeout <s>` Global timeout hint (http=12s, tcp/udp=3s by default)
- `--ports <list>` TCP ports to test (default `80,443`)
- `--no-trace` Disable system `tracert` wrapper
- `--verbose` Verbose logging
- `--json` Also print a short JSON summary to stdout
- `--help` Show help

Default targets: `youtube.com, discord.com, google.com, example.com`.

## Report format (JSON)

Top-level shape:

```
{
  "run_at": "2025-10-24T15:00:00Z",
  "cli": "--targets youtube.com,discord.com --report report.json",
  "ext_ip": "185.53.46.108",
  "summary": {
    "dns": "WARN|OK|DNS_FILTERED|DNS_BOGUS",
    "tcp": "OK|FAIL|UNKNOWN",
    "udp": "OK|FAIL|UNKNOWN",
    "tls": "OK|SUSPECT|FAIL|UNKNOWN",
    "rst_inject": "UNKNOWN"
  },
  "targets": {
    "host": {
      "system_dns": ["A-IPv4"],
      "doh": ["A-IPv4"],
      "dns_status": "OK|WARN|DNS_FILTERED|DNS_BOGUS",
      "tcp": [{"ip":"1.2.3.4","port":443,"open":true,"elapsed_ms":50}],
      "http": [{"url":"https://host","success":true,"status":200,"serverHeader":"...","cert_cn":"..."}],
      "traceroute": {"hops":[{"hop":1,"ip":"10.0.0.1","status":"Hop|TimedOut"}],"rawOutput":["..."]}
    }
  },
  "udp_test": {"target":"1.1.1.1","reply":false,"rtt_ms":null}
}
```

## Status logic

- DNS:
  - `DNS_FILTERED` if system DNS returns no A while DoH has answers
  - `DNS_BOGUS` if any system A is in RFC1918, 127.0.0.0/8, or 0.0.0.0/8
  - `WARN` if system and DoH sets are disjoint (possible CDN/geo)
  - `OK` otherwise
- TCP: `OK` if any port open across all targets; `FAIL` otherwise
- UDP: `OK` if UDP DNS reply from `1.1.1.1:53` received; `FAIL` on timeout/error
- TLS: `SUSPECT` if TCP 443 open but HTTPS consistently fails for a target; else `OK` if any 2xx/3xx; `FAIL` if no success and targets present
- RST heuristic: `UNKNOWN` (only timing-based without pcap)

## Notes

- No external binaries used at runtime except optional `tracert` wrapper on Windows. If `tracert` is unavailable, traceroute is skipped.
- No raw sockets or packet capture in the main build.
- No data is uploaded by default; `report.json` is stored locally. If you need an upload option, add a dedicated flag and token flow.

