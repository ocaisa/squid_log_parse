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
    """Return the PTR hostname, or an empty string if unavailable."""
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return hostname.rstrip(".").lower()
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return ""


def analyse_logs(
    log_files,
    geoip_db,
    threshold=1.0,
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
    # Parse Squid logs and aggregate requests
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

                    # Look up country only once per unique IP.
                    if client_ip not in ip_country_cache:
                        try:
                            result = reader.country(client_ip)
                            code = result.country.iso_code
                            name = result.country.name

                            ip_country_cache[client_ip] = (
                                (code, name or code) if code else None
                            )

                        except (
                            geoip2.errors.AddressNotFoundError,
                            ValueError,
                        ):
                            ip_country_cache[client_ip] = None

                    country_info = ip_country_cache[client_ip]

                    if country_info is None:
                        unknown += 1
                        continue

                    code, _ = country_info
                    country_requests[code] += 1
                    country_bytes[code] += response_bytes

    print("\nAnalysis complete")
    print("=" * 65)
    print(f"Total requests:       {total:,}")
    print(f"Countries identified: {len(country_requests)}")
    print(f"Unmapped requests:    {unknown:,}")
    print(f"Unique client IPs:    {len(ip_requests):,}")

    if total == 0:
        print("No valid log entries found.")
        return

    # ---------------------------------------------------------
    # Select IPs above the request threshold BEFORE DNS lookups
    # ---------------------------------------------------------
    active_ips = [
        (ip, count)
        for ip, count in ip_requests.most_common()
        if count / total * 100 >= threshold
    ]

    # ---------------------------------------------------------
    # Reverse DNS ONLY for IPs above the threshold
    # ---------------------------------------------------------
    hostnames = {}

    if enable_reverse_dns and active_ips:
        print(
            f"\nReverse DNS lookup for {len(active_ips)} IP(s) "
            f"above the {threshold:.2f}% threshold..."
        )

        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)

        try:
            with ThreadPoolExecutor(max_workers=dns_workers) as executor:
                futures = {
                    executor.submit(reverse_dns, ip): ip
                    for ip, count in active_ips
                }

                completed = 0

                for future in as_completed(futures):
                    ip = futures[future]

                    try:
                        hostnames[ip] = future.result()
                    except Exception:
                        hostnames[ip] = ""

                    completed += 1

                    if completed % 100 == 0:
                        print(
                            f"  DNS completed: {completed:,}/"
                            f"{len(active_ips):,}"
                        )

        finally:
            socket.setdefaulttimeout(previous_timeout)

        resolved = sum(bool(name) for name in hostnames.values())
        print(
            f"Resolved hostnames: {resolved}/{len(active_ips)}"
        )

    else:
        print("\nReverse DNS disabled or no IPs above threshold.")

    # ---------------------------------------------------------
    # Print high-volume client IPs
    # ---------------------------------------------------------
    print(
        f"\nClient IPs responsible for >= {threshold:.2f}% "
        "of requests"
    )
    print("-" * 105)
    print(
        f"{'Client IP':<40} {'Requests':>12} "
        f"{'Share':>9}  Hostname"
    )
    print("-" * 105)

    for ip, count in active_ips:
        percentage = count / total * 100
        hostname = hostnames.get(ip, "") or "(no PTR record)"

        print(
            f"{ip:<40} {count:>12,} "
            f"{percentage:>8.2f}%  {hostname}"
        )

    if not active_ips:
        print("No client IPs reached the threshold.")

    print("-" * 105)

    # ---------------------------------------------------------
    # Export ALL client IPs to CSV
    # DNS is populated only for IPs above the threshold.
    # ---------------------------------------------------------
    ip_rows = [
        {
            "client_ip": ip,
            "reverse_dns": hostnames.get(ip, ""),
            "requests": count,
            "percentage": round(count / total * 100, 4),
            "above_threshold": count / total * 100 >= threshold,
        }
        for ip, count in ip_requests.most_common()
    ]

    ip_df = pd.DataFrame(ip_rows)
    ip_csv = "squid_ip_statistics.csv"
    ip_df.to_csv(ip_csv, index=False)

    print(f"\nIP statistics saved to {ip_csv}")

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

    country_csv = "squid_country_statistics.csv"
    country_df.to_csv(country_csv, index=False)

    print(f"Country statistics saved to {country_csv}")

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
        geo={
            "showframe": False,
            "showcoastlines": True,
        },
    )

    output = "squid_country_heatmap.html"
    fig.write_html(output, auto_open=True)

    print(f"\nHeat map saved to {output}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyse Squid logs, generate a country heat map, "
            "and report high-volume client IPs with reverse DNS."
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
        help="Path to the MaxMind GeoLite2 Country database",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Minimum percentage for IP report (default: 1)",
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

    if args.dns_workers < 1:
        parser.error("--dns-workers must be at least 1")

    if not Path(args.geoip).is_file():
        parser.error(
            f"GeoIP database not found: {args.geoip}"
        )

    for filename in args.logs:
        if not Path(filename).is_file():
            parser.error(f"Log file not found: {filename}")

    analyse_logs(
        args.logs,
        args.geoip,
        threshold=args.threshold,
        enable_reverse_dns=not args.no_reverse_dns,
        dns_workers=args.dns_workers,
    )


if __name__ == "__main__":
    main()

