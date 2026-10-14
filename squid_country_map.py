
#!/usr/bin/env python3

import argparse
import gzip
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import geoip2.database
import pandas as pd
import plotly.express as px
import pycountry


def open_log(filename):
    """Open plain-text or gzip-compressed Squid logs."""
    if str(filename).endswith(".gz"):
        return gzip.open(filename, "rt", errors="replace")
    return open(filename, "rt", errors="replace")


def reverse_dns(ip):
    """Return PTR hostname or an empty string if unavailable."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".").lower()
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return ""


def analyse_logs(
    log_files,
    geoip_db,
    asn_db,
    ip_threshold=1.0,
    organisation_threshold=1.0,
    enable_reverse_dns=True,
    dns_workers=32,
):
    country_requests = Counter()
    country_bytes = Counter()
    ip_requests = Counter()
    ip_country_cache = {}

    total = 0
    unknown = 0

    # ---------------------------------------------------------
    # Parse Squid logs and aggregate requests by country and IP
    # ---------------------------------------------------------
    with geoip2.database.Reader(str(geoip_db)) as reader:
        for filename in log_files:
            print(f"Reading {filename}...")

            with open_log(filename) as logfile:
                for line in logfile:
                    fields = line.split()

                    # Standard Squid access.log:
                    # timestamp elapsed client status bytes method URL ...
                    if len(fields) < 7:
                        continue

                    client_ip = fields[2]

                    try:
                        response_bytes = int(fields[4])
                    except ValueError:
                        continue

                    total += 1
                    ip_requests[client_ip] += 1

                    # Cache country lookup for each unique IP.
                    if client_ip not in ip_country_cache:
                        try:
                            result = reader.country(client_ip)
                            code = result.country.iso_code

                            ip_country_cache[client_ip] = (
                                code if code else None
                            )
                        except (
                            geoip2.errors.AddressNotFoundError,
                            ValueError,
                        ):
                            ip_country_cache[client_ip] = None

                    code = ip_country_cache[client_ip]

                    if not code:
                        unknown += 1
                        continue

                    country_requests[code] += 1
                    country_bytes[code] += response_bytes

    print("\nAnalysis complete")
    print("=" * 70)
    print(f"Total requests:       {total:,}")
    print(f"Countries identified: {len(country_requests)}")
    print(f"Unmapped requests:    {unknown:,}")
    print(f"Unique client IPs:    {len(ip_requests):,}")

    if total == 0:
        print("No valid log entries found.")
        return

    # ---------------------------------------------------------
    # ASN lookup: map every unique IP to its network organisation
    # ---------------------------------------------------------
    ip_organisation = {}

    print("\nLooking up ASN organisations...")

    with geoip2.database.Reader(str(asn_db)) as reader:
        for ip in ip_requests:
            try:
                result = reader.asn(ip)
                number = result.autonomous_system_number
                name = result.autonomous_system_organization

                if number and name:
                    organisation = f"AS{number} - {name}"
                elif number:
                    organisation = f"AS{number}"
                elif name:
                    organisation = name
                else:
                    organisation = "Unknown"

            except (
                geoip2.errors.AddressNotFoundError,
                ValueError,
            ):
                organisation = "Unknown"

            ip_organisation[ip] = organisation

    # Aggregate requests by organisation.
    organisation_requests = Counter()

    for ip, count in ip_requests.items():
        organisation_requests[ip_organisation[ip]] += count

    # ---------------------------------------------------------
    # Reverse DNS only for IPs above the IP threshold
    # ---------------------------------------------------------
    active_ips = [
        (ip, count)
        for ip, count in ip_requests.most_common()
        if count / total * 100 >= ip_threshold
    ]

    hostnames = {}

    if enable_reverse_dns and active_ips:
        print(
            f"\nReverse DNS for {len(active_ips)} IP(s) "
            f"at or above {ip_threshold:.2f}%..."
        )

        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)

        try:
            with ThreadPoolExecutor(max_workers=dns_workers) as executor:
                futures = {
                    executor.submit(reverse_dns, ip): ip
                    for ip, _ in active_ips
                }

                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        hostnames[ip] = future.result()
                    except Exception:
                        hostnames[ip] = ""
        finally:
            socket.setdefaulttimeout(previous_timeout)

        resolved = sum(bool(host) for host in hostnames.values())
        print(f"Resolved hostnames: {resolved}/{len(active_ips)}")

    # ---------------------------------------------------------
    # Report 1: individual client IPs
    # ---------------------------------------------------------
    print(
        f"\nIP addresses with >= {ip_threshold:.2f}% of requests"
    )
    print("-" * 125)
    print(
        f"{'Client IP':<40} {'Requests':>12} "
        f"{'Share':>9}  {'Organisation':<35} Hostname"
    )
    print("-" * 125)

    for ip, count in active_ips:
        percentage = count / total * 100
        organisation = ip_organisation[ip]
        hostname = hostnames.get(ip, "") or "(no PTR record)"

        print(
            f"{ip:<40} {count:>12,} {percentage:>8.2f}%  "
            f"{organisation[:35]:<35} {hostname}"
        )

    if not active_ips:
        print("No IPs reached the threshold.")

    print("-" * 125)

    # Export all IPs. DNS is populated only for qualifying IPs.
    ip_rows = [
        {
            "client_ip": ip,
            "reverse_dns": hostnames.get(ip, ""),
            "asn_organisation": ip_organisation[ip],
            "requests": count,
            "percentage": round(count / total * 100, 4),
            "above_threshold": count / total * 100 >= ip_threshold,
        }
        for ip, count in ip_requests.most_common()
    ]

    pd.DataFrame(ip_rows).to_csv(
        "squid_ip_statistics.csv", index=False
    )
    print("\nIP statistics saved to squid_ip_statistics.csv")

    # ---------------------------------------------------------
    # Report 2: organisations grouped by ASN
    # ---------------------------------------------------------
    print(
        f"\nOrganisations with >= {organisation_threshold:.2f}% "
        "of requests"
    )
    print("-" * 100)
    print(f"{'Organisation':<65} {'Requests':>12} {'Share':>9}")
    print("-" * 100)

    active_organisations = []

    for organisation, count in organisation_requests.most_common():
        percentage = count / total * 100

        if percentage >= organisation_threshold:
            active_organisations.append((organisation, count))
            print(
                f"{organisation[:65]:<65} "
                f"{count:>12,} {percentage:>8.2f}%"
            )

    if not active_organisations:
        print("No organisations reached the threshold.")

    print("-" * 100)

    organisation_rows = [
        {
            "organisation": organisation,
            "requests": count,
            "percentage": round(count / total * 100, 4),
            "above_threshold": count / total * 100
            >= organisation_threshold,
        }
        for organisation, count in organisation_requests.most_common()
    ]

    pd.DataFrame(organisation_rows).to_csv(
        "squid_organisation_statistics.csv", index=False
    )
    print(
        "Organisation statistics saved to "
        "squid_organisation_statistics.csv"
    )

    # ---------------------------------------------------------
    # Country statistics and CSV
    # ---------------------------------------------------------
    country_rows = []

    for code, count in country_requests.items():
        country = pycountry.countries.get(alpha_2=code)

        country_rows.append({
            "country": country.name if country else code,
            "iso2": code,
            "iso3": country.alpha_3 if country else None,
            "requests": count,
            "percentage": round(count / total * 100, 4),
            "bandwidth_MB": round(
                country_bytes[code] / (1024 * 1024), 2
            ),
        })

    country_df = pd.DataFrame(country_rows)
    country_df = country_df.dropna(subset=["iso3"])
    country_df = country_df.sort_values(
        "requests", ascending=False
    )

    country_df.to_csv(
        "squid_country_statistics.csv", index=False
    )
    print("Country statistics saved to squid_country_statistics.csv")

    print("\nTop 10 countries:")
    if not country_df.empty:
        print(
            country_df[
                ["country", "requests", "percentage", "bandwidth_MB"]
            ].head(10).to_string(index=False)
        )

    if country_df.empty:
        print("No country data available to plot.")
        return

    # ---------------------------------------------------------
    # Interactive world heat map
    # ---------------------------------------------------------
    fig = px.choropleth(
        country_df,
        locations="iso3",
        color="requests",
        hover_name="country",
        hover_data={
            "requests": ":,",
            "percentage": ":.2f",
            "bandwidth_MB": True,
            "iso3": False,
            "iso2": False,
        },
        color_continuous_scale="YlOrRd",
        projection="natural earth",
        title="Squid Proxy Requests by Country",
        labels={
            "requests": "Requests",
            "percentage": "Share of all requests (%)",
            "bandwidth_MB": "Bandwidth (MiB)",
        },
    )

    fig.update_layout(
        template="plotly_dark",
        geo={"showframe": False, "showcoastlines": True},
    )

    output = "squid_country_heatmap.html"
    fig.write_html(output, auto_open=True)
    print(f"\nHeat map saved to {output}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyse Squid logs by country, client IP, "
            "and ASN organisation."
        )
    )

    parser.add_argument(
        "logs",
        nargs="+",
        help="Squid log files, including .gz rotated logs",
    )

    parser.add_argument(
        "--geoip",
        default="GeoLite2-Country.mmdb",
        help="Path to MaxMind GeoLite2 Country database",
    )

    parser.add_argument(
        "--asn-db",
        default="GeoLite2-ASN.mmdb",
        help="Path to MaxMind GeoLite2 ASN database",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Minimum IP percentage (default: 1)",
    )

    parser.add_argument(
        "--organisation-threshold",
        type=float,
        default=1.0,
        help="Minimum organisation percentage (default: 1)",
    )

    parser.add_argument(
        "--no-reverse-dns",
        action="store_true",
        help="Skip reverse DNS lookups",
    )

    parser.add_argument(
        "--dns-workers",
        type=int,
        default=32,
        help="Concurrent DNS workers (default: 32)",
    )

    args = parser.parse_args()

    if not 0 <= args.threshold <= 100:
        parser.error("--threshold must be between 0 and 100")

    if not 0 <= args.organisation_threshold <= 100:
        parser.error(
            "--organisation-threshold must be between 0 and 100"
        )

    if args.dns_workers < 1:
        parser.error("--dns-workers must be at least 1")

    for db in (args.geoip, args.asn_db):
        if not Path(db).is_file():
            parser.error(f"Database not found: {db}")

    for filename in args.logs:
        if not Path(filename).is_file():
            parser.error(f"Log file not found: {filename}")

    analyse_logs(
        args.logs,
        args.geoip,
        args.asn_db,
        ip_threshold=args.threshold,
        organisation_threshold=args.organisation_threshold,
        enable_reverse_dns=not args.no_reverse_dns,
        dns_workers=args.dns_workers,
    )


if __name__ == "__main__":
    main()

