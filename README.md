# Squid Access Log Analyser

A Python tool for analysing Squid proxy access logs. It summarises traffic by country, client IP address, and network organisation (ASN), and generates an interactive world map showing the geographical distribution of requests.

The analyser supports plain-text and gzip-compressed Squid access logs.

## Features

- Parses Squid access logs, including `.gz` files.
- Maps client IP addresses to countries using the MaxMind GeoLite2 Country database.
- Identifies network organisations using the MaxMind GeoLite2 ASN database.
- Generates an interactive Plotly world map of requests by country.
- Produces CSV reports for IP addresses, network organisations, and countries.
- Calculates request percentages and country-level bandwidth usage.
- Performs reverse DNS lookups only for IP addresses meeting the configured threshold.
- Supports configurable IP and organisation thresholds.
- Uses concurrent reverse DNS lookups to improve performance.

## Requirements

- Python 3.9 or newer recommended.
- A Squid access log.
- The GeoLite2 Country and ASN database files.
- The Python packages listed in `requirements.txt`.

## Installation

Clone or download this project and enter its directory:

```bash
cd squid_log_parse
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Download the GeoLite2 databases

The analyser requires two MaxMind GeoLite2 databases:

- **GeoLite2 Country** — maps IP addresses to countries.
- **GeoLite2 ASN** — identifies Autonomous System Numbers and their associated network organisations.

You can obtain these databases from the [P3TERX/GeoLite.mmdb GitHub repository](https://github.com/P3TERX/GeoLite.mmdb).

The default filenames and paths expected by the script are:

```text
GeoLite2-Country.mmdb
GeoLite2-ASN.mmdb
```

If your databases are stored elsewhere, use the `--geoip` and `--asn-db` command-line options.

### Database licensing

These databases are MaxMind GeoLite2 data distributed through a third-party repository. Review the [GeoLite2 End User Licence Agreement](https://www.maxmind.com/en/geolite2/eula) and the repository's terms before using or redistributing the files.

The third-party repository is not the official MaxMind download portal. Refresh the databases periodically to keep country and ASN information reasonably current.

## Usage

Activate the virtual environment before running the script:

```bash
source venv/bin/activate
```

### Basic usage

Analyse a gzip-compressed Squid access log:

```bash
python squid_country_map.py access.log-20260913.gz
```

Or analyse an uncompressed log:

```bash
python squid_country_map.py access.log
```

By default, IP addresses and organisations must each account for at least **1% of all valid parsed requests** to meet their respective reporting thresholds.

Reverse DNS is enabled by default for IP addresses meeting the IP threshold.

### Configure the thresholds

Set the IP address threshold to 2%:

```bash
python squid_country_map.py access.log-20260913.gz --threshold 2
```

Set the organisation threshold to 3%:

```bash
python squid_country_map.py access.log-20260913.gz --organisation-threshold 3
```

Set both thresholds explicitly to 1%:

```bash
python squid_country_map.py access.log-20260913.gz \
  --threshold 1 \
  --organisation-threshold 1
```

The thresholds are independent. For example, an IP address can meet the IP threshold even if its organisation does not meet the organisation threshold.

### Disable reverse DNS lookups

To skip hostname resolution and speed up analysis:

```bash
python squid_country_map.py access.log-20260913.gz --no-reverse-dns
```

Reverse DNS lookups can introduce delays and depend on the availability and responsiveness of DNS servers.

### Configure DNS concurrency

The default number of concurrent DNS workers is 32. To change it:

```bash
python squid_country_map.py access.log-20260913.gz --dns-workers 64
```

Increasing the worker count may improve throughput, but can also increase DNS traffic and timeouts.

### Specify database locations

If the database files are stored elsewhere:

```bash
python squid_country_map.py access.log-20260913.gz \
  --geoip /path/to/GeoLite2-Country.mmdb \
  --asn-db /path/to/GeoLite2-ASN.mmdb
```

Combine these options as required.

## Output files

The analyser generates the following reports in its output directory, normally the current working directory.

### `squid_country_heatmap.html`

An interactive Plotly choropleth map showing request distribution by country.

Open the file in a web browser to explore the geographical distribution of requests.

### `squid_ip_statistics.csv`

Statistics for individual client IP addresses, including:

| Column | Description |
|---|---|
| IP address | Client IP address from the access log |
| Hostname | Reverse DNS hostname, when resolved for a qualifying IP |
| ASN organisation | Network organisation identified by the ASN database |
| Requests | Number of requests from the IP |
| Percentage | Percentage of all valid parsed requests |
| Above threshold | Whether the IP meets the configured IP threshold |

Hostname values may be empty when reverse DNS is disabled, the lookup fails, or no hostname is available.

### `squid_organisation_statistics.csv`

Statistics grouped by network organisation:

| Column | Description |
|---|---|
| ASN organisation | Organisation associated with the network's ASN |
| Requests | Number of requests attributed to the organisation |
| Percentage | Percentage of all valid parsed requests |
| Above threshold | Whether the organisation meets its configured threshold |

Organisation attribution depends on the available ASN database. Unidentified networks may be grouped under an unknown or unavailable organisation value, depending on the script's implementation.

### `squid_country_statistics.csv`

Statistics grouped by country:

| Column | Description |
|---|---|
| Country | Country name |
| Country code | ISO country code, where available |
| Requests | Number of requests attributed to the country |
| Percentage | Percentage of all valid parsed requests |
| Bandwidth MB | Total response bytes attributed to the country, converted to megabytes |

Exact column names depend on the names defined in the script.

## How the analysis works

### Request counting

The analyser reads each log entry and extracts the client IP address and response byte count from the Squid access log fields.

Only entries that can be parsed successfully and have a numeric response byte field contribute to the valid-request denominator.

Percentages are calculated as:

```text
percentage = requests / total_valid_requests * 100
```

Requests from IP addresses that cannot be mapped to a country are still included in the overall request denominator. Consequently, the sum of country percentages can be less than 100%.

### Country identification

Client IP addresses are looked up in the GeoLite2 Country database. Country-level request counts and bandwidth totals are then calculated from the available results.

GeoIP mapping is approximate. VPNs, proxies, hosting networks, mobile providers, and incorrectly geolocated IP ranges can affect the apparent location.

### Network organisation identification

The GeoLite2 ASN database is used to associate IP addresses with an Autonomous System Number and its registered organisation.

This identifies the network associated with an IP address; it does **not** definitively identify the cloud provider, product, service, or purpose of the traffic. The report does not rely on official cloud-provider IP range feeds.

### Reverse DNS

Reverse DNS is performed only for IP addresses meeting the configured IP threshold. This avoids unnecessary lookups for the long tail of low-volume clients.

Lookups use Python's `socket.gethostbyaddr` and a thread pool to run multiple queries concurrently. DNS results are best-effort and may be missing or outdated.

## Example project layout

```text
squid_log_parse/
├── squid_country_map.py
├── requirements.txt
├── README.md
├── GeoLite2-Country.mmdb
├── GeoLite2-ASN.mmdb
├── access.log-20260913.gz
└── venv/
```

The input log and virtual environment do not have to reside in the project directory.

## Troubleshooting

### Missing Python modules

Make sure the virtual environment is active and dependencies are installed:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### GeoIP database not found

Check that both database files exist and that their paths match the script's arguments or defaults.

### Empty hostname values

Reverse DNS may be disabled, the IP address may not have a PTR record, or the lookup may have failed or timed out. Empty hostnames do not necessarily indicate a problem with the log.

### Country totals do not add up to 100%

Some IP addresses may not be mapped to a country. These requests remain part of the total valid-request denominator, so the country percentages may sum to less than 100%.

### Slow processing

For large logs, processing time depends on the number of entries, database lookups, disk performance, and DNS responsiveness. Try `--no-reverse-dns` to determine whether hostname resolution is contributing significantly to runtime.

## Privacy considerations

Squid access logs can contain sensitive information, including client IP addresses, requested URLs, and usage patterns. Treat input logs and generated reports as potentially sensitive.

Reverse DNS sends lookup requests to the DNS infrastructure configured on the host. Consider your organisation's privacy and security requirements before enabling it.

Avoid publishing generated CSV files or interactive maps if they could disclose sensitive network usage information.

## Licence and attribution

This project uses third-party Python packages and GeoLite2 databases. Consult their respective licences and terms before redistribution or commercial use.

- [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)
- [MaxMind GeoLite2 licence](https://www.maxmind.com/en/geolite2/eula)
- [Plotly Python documentation](https://plotly.com/python/)
- [GeoIP2 Python documentation](https://geoip2.readthedocs.io/)

## Disclaimer

Country and ASN information is approximate and depends on the accuracy and freshness of the underlying databases. Results should be interpreted as an analytical aid rather than definitive proof of a client's physical location or service provider.

