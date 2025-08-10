#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kms_dns_discovery.py — обнаружение KMS-серверов через DNS SRV (_vlmcs._tcp)

Функции:
- Поиск SRV через dnspython (если установлен) либо через nslookup/dig
- (Опционально) резолвинг A/AAAA адресов целевых хостов
- (Опционально) проверка TCP-доступности порта (по умолчанию 1688)
- Вывод в форматах table/json/csv
- Коды возврата:
  0 — найдено (и/или доступен порт при --verify-port)
  2 — SRV не найдены (NXDOMAIN/NoData)
  3 — SRV найдены, но все проверки TCP провалились (если включен --verify-port)
  1 — иные ошибки
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Sequence, Tuple

__VERSION__ = "1.0.0"

DNSSPY_AVAILABLE = False
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception

    DNSSPY_AVAILABLE = True
except Exception:
    DNSSPY_AVAILABLE = False


@dataclasses.dataclass
class SRVRecord:
    host: str
    port: int
    priority: int
    weight: int
    ttl: Optional[int] = None
    addresses: List[str] = dataclasses.field(default_factory=list)
    reachable: Optional[bool] = None


# ------------------------- Utilities ------------------------- #
def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def is_windows() -> bool:
    return os.name == "nt" or platform.system().lower().startswith("win")


def validate_domain(d: str) -> str:
    d = d.strip()
    d = d.lstrip(".")
    # очень простой контроль допустимых символов домена
    if not re.fullmatch(r"[A-Za-z0-9._-]+", d):
        raise ValueError(f"Invalid domain: {d}")
    return d


def fqdn_for_query(domain: Optional[str]) -> str:
    if domain:
        return f"_vlmcs._tcp.{validate_domain(domain)}"
    return "_vlmcs._tcp"


# ------------------------- DNS via dnspython ------------------------- #
def query_srv_dnspython(qname: str, nameservers: Sequence[str], timeout: float, tries: int, raw: bool):
    resolver = dns.resolver.Resolver(configure=True)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.lifetime = timeout
    last_err = None
    for attempt in range(tries):
        try:
            answer = resolver.resolve(qname, "SRV")
            if raw:
                eprint("[raw] dnspython answer:", answer.response.to_text())
            results: List[SRVRecord] = []
            ttl = None
            try:
                ttl = min(r.ttl for r in answer.response.answer for r in r.items if hasattr(r, "ttl"))
            except Exception:
                ttl = None
            for rr in answer:
                # rr: priority, weight, port, target
                results.append(
                    SRVRecord(
                        host=str(rr.target).rstrip("."),
                        port=int(rr.port),
                        priority=int(rr.priority),
                        weight=int(rr.weight),
                        ttl=ttl,
                    )
                )
            return results, None  # None -> no “not found” mark
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            last_err = e
            return [], "not_found"
        except (dns.exception.Timeout, dns.resolver.YXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
            last_err = e
            if attempt < tries - 1:
                continue
            else:
                raise
        except Exception as e:
            last_err = e
            raise
    raise last_err if last_err else RuntimeError("Unknown DNS error")


def resolve_addresses_dnspython(hosts: Sequence[str], nameservers: Sequence[str], timeout: float) -> dict:
    resolver = dns.resolver.Resolver(configure=True)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.lifetime = timeout

    out: dict[str, List[str]] = {}
    for h in hosts:
        addrs: List[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ans = resolver.resolve(h, rtype)
                for r in ans:
                    addrs.append(r.address)
            except Exception:
                pass
        out[h] = addrs
    return out


# ------------------------- DNS via system tools ------------------------- #
_SRVBLOCK_KEYS = ("priority", "weight", "port", "svr hostname", "target", "host")


def _parse_nslookup_output_srv(stdout: str) -> List[SRVRecord]:
    """
    Парсинг типового вывода nslookup -type=SRV _vlmcs._tcp[.domain]
    Поддержка блоков вида:
      _vlmcs._tcp.domain SRV service location:
            priority = 0
            weight = 100
            port = 1688
            svr hostname = kms.domain
    А также строк dig-подобного формата, если встречаются.
    """
    records: List[SRVRecord] = []

    # Вариант dig-формата в nslookup некоторых систем:
    dig_like = re.compile(
        r"^\s*\S+\s+(\d+)\s+IN\s+SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\.?\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in dig_like.finditer(stdout):
        ttl = int(m.group(1))
        prio = int(m.group(2))
        weight = int(m.group(3))
        port = int(m.group(4))
        target = m.group(5).rstrip(".")
        records.append(SRVRecord(host=target, port=port, priority=prio, weight=weight, ttl=ttl))

    if records:
        return records

    # Блочный формат Windows nslookup
    lines = stdout.splitlines()
    i = 0
    while i < len(lines):
        if "SRV service location" in lines[i]:
            prio = weight = port = None
            target = None
            ttl = None
            j = i + 1
            while j < len(lines) and (lines[j].strip().startswith(tuple(k for k in _SRVBLOCK_KEYS)) or "=" in lines[j]):
                line = lines[j].strip()
                # priority = 0
                m = re.match(r"priority\s*=\s*(\d+)", line, re.IGNORECASE)
                if m:
                    prio = int(m.group(1))
                m = re.match(r"weight\s*=\s*(\d+)", line, re.IGNORECASE)
                if m:
                    weight = int(m.group(1))
                m = re.match(r"port\s*=\s*(\d+)", line, re.IGNORECASE)
                if m:
                    port = int(m.group(1))
                m = re.match(r"(svr hostname|target|host)\s*=\s*(\S+)", line, re.IGNORECASE)
                if m:
                    target = m.group(2).rstrip(".")
                j += 1
            if prio is not None and weight is not None and port is not None and target:
                records.append(SRVRecord(host=target, port=port, priority=prio, weight=weight, ttl=ttl))
            i = j
        else:
            i += 1
    return records


def query_srv_nslookup(qname: str, nameservers: Sequence[str], timeout: float, tries: int, raw: bool):
    """
    Вызывает nslookup. Если передан nameserver, выполнит по каждому до успеха или исчерпания попыток.
    nslookup не имеет явного параметра таймаута, но многие сборки уважают системный резолвер; попробуем несколько попыток.
    """
    servers = nameservers or [None]
    last_stdout = ""
    for attempt in range(tries):
        for ns in servers:
            cmd = ["nslookup", "-type=SRV", qname]
            if ns:
                cmd.append(ns)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, int(timeout) + 1))
                stdout = proc.stdout or ""
                last_stdout = stdout
                if raw:
                    eprint(f"[raw] {' '.join(shlex.quote(c) for c in cmd)}")
                    eprint(stdout)
                records = _parse_nslookup_output_srv(stdout)
                if records:
                    return records, None
                # Если в выводе явно указано NXDOMAIN / Non-existent domain
                if re.search(r"(NXDOMAIN|Non-existent domain|No answer|server can't find)", stdout, re.IGNORECASE):
                    return [], "not_found"
            except subprocess.TimeoutExpired:
                continue
            except FileNotFoundError:
                # nslookup отсутствует — попробуем dig
                return query_srv_dig(qname, nameservers, timeout, tries, raw)
    # Если пусто — либо не найдено, либо не распознали вывод
    if last_stdout and re.search(r"(NXDOMAIN|Non-existent domain|No answer|server can't find)", last_stdout, re.IGNORECASE):
        return [], "not_found"
    return [], None


def _parse_dig_output_srv(stdout: str) -> List[SRVRecord]:
    records: List[SRVRecord] = []
    # Пример: _vlmcs._tcp.example.com. 3600 IN SRV 0 100 1688 kms.example.com.
    rx = re.compile(
        r"^\s*\S+\s+(\d+)\s+IN\s+SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\.?\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in rx.finditer(stdout):
        ttl = int(m.group(1))
        prio = int(m.group(2))
        weight = int(m.group(3))
        port = int(m.group(4))
        target = m.group(5).rstrip(".")
        records.append(SRVRecord(host=target, port=port, priority=prio, weight=weight, ttl=ttl))
    return records


def query_srv_dig(qname: str, nameservers: Sequence[str], timeout: float, tries: int, raw: bool):
    servers = nameservers or [None]
    for attempt in range(tries):
        for ns in servers:
            cmd = ["dig", f"+time={max(1, int(timeout))}", f"+tries=1", "SRV", qname]
            if ns:
                cmd.append(f"@{ns}")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(2, int(timeout) + 2))
                stdout = proc.stdout or ""
                if raw:
                    eprint(f"[raw] {' '.join(shlex.quote(c) for c in cmd)}")
                    eprint(stdout)
                records = _parse_dig_output_srv(stdout)
                if records:
                    return records, None
                # dig печатает status: NXDOMAIN при отсутствии
                if re.search(r"status:\s*NXDOMAIN", stdout, re.IGNORECASE):
                    return [], "not_found"
            except subprocess.TimeoutExpired:
                continue
            except FileNotFoundError:
                # dig отсутствует — больше вариантов нет
                return [], None
    return [], None


# ------------------------- Resolve addresses (fallbacks) ------------------------- #
def resolve_addresses_fallback(hosts: Sequence[str]) -> dict:
    out: dict[str, List[str]] = {}
    for h in hosts:
        addrs: List[str] = []
        try:
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    infos = socket.getaddrinfo(h, None, family, socket.SOCK_STREAM)
                    for info in infos:
                        sockaddr = info[4]
                        ip = sockaddr[0]
                        try:
                            # нормализуем
                            ipaddress.ip_address(ip)
                        except Exception:
                            continue
                        if ip not in addrs:
                            addrs.append(ip)
                except socket.gaierror:
                    pass
        except Exception:
            pass
        out[h] = addrs
    return out


# ------------------------- TCP check ------------------------- #
def tcp_check(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ------------------------- Formatting ------------------------- #
def format_table(records: List[SRVRecord], quiet: bool) -> str:
    headers = ["HOST", "PORT", "PRIO", "WEIGHT", "TTL", "ADDRESSES", "REACHABLE"]
    rows = []
    for r in records:
        rows.append(
            [
                r.host,
                str(r.port),
                str(r.priority),
                str(r.weight),
                "-" if r.ttl is None else str(r.ttl),
                "-" if not r.addresses else "; ".join(r.addresses),
                "-" if r.reachable is None else ("yes" if r.reachable else "no"),
            ]
        )

    # ширины
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def align(row):
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    out_lines = []
    if not quiet:
        out_lines.append(align(headers))
    out_lines += [align(r) for r in rows]
    return "\n".join(out_lines)


def format_json(q: str, records: List[SRVRecord]) -> str:
    payload = {
        "query": q,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [
            {
                "host": r.host,
                "port": r.port,
                "priority": r.priority,
                "weight": r.weight,
                "ttl": r.ttl,
                "addresses": r.addresses,
                "reachable": r.reachable,
            }
            for r in records
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def format_csv(records: List[SRVRecord]) -> str:
    from io import StringIO

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["host", "port", "priority", "weight", "ttl", "addresses", "reachable"])
    for r in records:
        writer.writerow(
            [
                r.host,
                r.port,
                r.priority,
                r.weight,
                "" if r.ttl is None else r.ttl,
                ";".join(r.addresses) if r.addresses else "",
                "" if r.reachable is None else ("true" if r.reachable else "false"),
            ]
        )
    return sio.getvalue().rstrip("\n")


# ------------------------- Main logic ------------------------- #
def discover_srv(
    qname: str,
    nameservers: Sequence[str],
    timeout: float,
    tries: int,
    raw: bool,
) -> Tuple[List[SRVRecord], Optional[str]]:
    """
    Возвращает (records, not_found_flag)
    not_found_flag == "not_found" означает NXDOMAIN/NoData
    """
    # 1) dnspython
    if DNSSPY_AVAILABLE:
        try:
            return query_srv_dnspython(qname, nameservers, timeout, tries, raw)
        except dns.resolver.NXDOMAIN:
            return [], "not_found"
        except dns.resolver.NoAnswer:
            return [], "not_found"
        except Exception as e:
            eprint(f"[dnspython] {e}. Falling back to system tools...")

    # 2) nslookup (fallback) -> dig (fallback)
    recs, nf = query_srv_nslookup(qname, nameservers, timeout, tries, raw)
    if recs or nf == "not_found":
        return recs, nf

    recs, nf = query_srv_dig(qname, nameservers, timeout, tries, raw)
    return recs, nf


def resolve_addresses(
    records: List[SRVRecord],
    nameservers: Sequence[str],
    timeout: float,
) -> None:
    hosts = sorted({r.host for r in records})
    if not hosts:
        return
    if DNSSPY_AVAILABLE:
        mapping = resolve_addresses_dnspython(hosts, nameservers, timeout)
    else:
        mapping = resolve_addresses_fallback(hosts)
    for r in records:
        r.addresses = mapping.get(r.host, [])


def verify_tcp(records: List[SRVRecord], port: int, timeout: float) -> None:
    with ThreadPoolExecutor(max_workers=min(10, max(1, len(records)))) as exe:
        futures = {exe.submit(tcp_check, r.host, port if port else r.port, timeout): r for r in records}
        for fut in as_completed(futures):
            r = futures[fut]
            ok = False
            try:
                ok = fut.result()
            except Exception:
                ok = False
            r.reachable = ok


def sort_records(records: List[SRVRecord]) -> List[SRVRecord]:
    return sorted(records, key=lambda r: (r.priority, -r.weight, r.host))


def parse_nameservers(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    if not values:
        return out
    for v in values:
        v = v.strip()
        # разрешаем ip:port, но dig/nslookup используют только ip; порт игнорируем
        if ":" in v and not re.match(r"^\[.*\]$", v):
            # IPv6 без [] — попробуем понять
            try:
                ipaddress.ip_address(v)
                out.append(v)
                continue
            except Exception:
                v = v.split(":")[0]
        out.append(v)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Discover KMS SRV records (_vlmcs._tcp) and optionally verify TCP connectivity.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--domain", help="Explicit DNS domain (e.g., corp.example.com)")
    p.add_argument("-n", "--nameserver", action="append", help="DNS server IP (repeatable)")
    p.add_argument("-t", "--timeout", type=float, default=3.0, help="DNS/TCP timeout seconds")
    p.add_argument("--tries", type=int, default=2, help="DNS query attempts")

    p.add_argument("--resolve-a", action="store_true", help="Resolve A/AAAA for targets")
    p.add_argument("-V", "--verify-port", action="store_true", help="Verify TCP reachability")
    p.add_argument("--port", type=int, default=1688, help="Port for TCP verification")

    p.add_argument("-f", "--format", choices=["table", "json", "csv"], default="table", help="Output format")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce logs to results only")

    p.add_argument("--raw", action="store_true", help="Print raw DNS tool output (debug)")
    p.add_argument("--version", action="store_true", help="Show version and exit")

    args = p.parse_args(argv)

    if args.version:
        print(__VERSION__)
        return 0

    try:
        qname = fqdn_for_query(args.domain)
    except ValueError as e:
        eprint(str(e))
        return 1

    nameservers = parse_nameservers(args.nameserver)

    try:
        records, not_found = discover_srv(qname, nameservers, args.timeout, args.tries, args.raw)
    except Exception as e:
        if not args.quiet:
            eprint(f"DNS error: {e}")
        return 1

    if not records:
        if not_found == "not_found":
            # SRV отсутствуют
            if args.format == "json":
                print(format_json(qname, []))
            elif args.format == "csv":
                print(format_csv([]))
            else:
                if not args.quiet:
                    print("No SRV records found.")
            return 2
        # иначе — пусто, но непонятно; считаем ошибкой
        if not args.quiet:
            eprint("No SRV records parsed (tool output unrecognized).")
        return 1

    # resolve addresses if requested
    if args.resolve_a:
        resolve_addresses(records, nameservers, args.timeout)

    # verify tcp if requested
    if args.verify_port:
        verify_tcp(records, args.port, args.timeout)

    # sort
    records = sort_records(records)

    # output
    if args.format == "json":
        print(format_json(qname, records))
    elif args.format == "csv":
        print(format_csv(records))
    else:
        print(format_table(records, args.quiet))

    # exit codes
    if args.verify_port:
        if any(r.reachable for r in records if r.reachable is not None):
            return 0
        else:
            # ни один не доступен
            return 3
    else:
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)