import argparse
import hashlib
import http.client
import json
import ssl
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit


MARKER = "{{FUZZ}}"


def read_request(path):
    raw = Path(path).read_bytes()
    head, sep, body = raw.partition(b"\r\n\r\n")

    if not sep:
        head, sep, body = raw.partition(b"\n\n")

    lines = head.decode("latin-1").replace("\r\n", "\n").split("\n")

    method, target, _ = lines[0].split(" ", 2)
    headers = []

    for line in lines[1:]:
        if not line or ":" not in line:
            continue

        k, v = line.split(":", 1)
        headers.append((k.strip(), v.lstrip()))

    return {
        "method": method,
        "target": target,
        "headers": headers,
        "body": body,
    }


def has_marker(req):
    if MARKER in req["target"]:
        return True

    if MARKER.encode() in req["body"]:
        return True

    for k, v in req["headers"]:
        if MARKER in k or MARKER in v:
            return True

    return False


def mutate(req, payload):
    p = payload.encode()

    return {
        "method": req["method"],
        "target": req["target"].replace(MARKER, payload),
        "headers": [
            (
                k.replace(MARKER, payload),
                v.replace(MARKER, payload),
            )
            for k, v in req["headers"]
        ],
        "body": req["body"].replace(MARKER.encode(), p),
    }


def clean_headers(headers, body):
    out = {}

    for k, v in headers:
        lk = k.lower()

        if lk in {
            "host",
            "content-length",
            "connection",
            "accept-encoding",
        }:
            continue

        out[k] = v

    if body:
        out["Content-Length"] = str(len(body))

    out["Connection"] = "close"
    out["Accept-Encoding"] = "identity"

    return out


def json_shape(data):
    try:
        obj = json.loads(data)
    except Exception:
        return None

    def walk(x):
        if isinstance(x, dict):
            return {
                k: walk(v)
                for k, v in sorted(x.items())
            }

        if isinstance(x, list):
            if not x:
                return []

            shapes = [walk(v) for v in x[:6]]
            return shapes

        return type(x).__name__

    shape = json.dumps(walk(obj), sort_keys=True, separators=(",", ":"))

    return hashlib.sha1(shape.encode()).hexdigest()[:10]


def body_sig(data):
    return hashlib.sha1(data).hexdigest()[:12]


def connect(base, timeout):
    u = urlsplit(base)
    host = u.hostname
    port = u.port

    if u.scheme == "https":
        ctx = ssl.create_default_context()
        return http.client.HTTPSConnection(
            host,
            port or 443,
            timeout=timeout,
            context=ctx,
        )

    return http.client.HTTPConnection(
        host,
        port or 80,
        timeout=timeout,
    )


def send(base, req, payload, timeout):
    changed = mutate(req, payload)
    headers = clean_headers(changed["headers"], changed["body"])

    conn = connect(base, timeout)
    started = time.perf_counter()

    try:
        conn.request(
            changed["method"],
            changed["target"],
            body=changed["body"] or None,
            headers=headers,
        )

        r = conn.getresponse()
        data = r.read()

        elapsed = time.perf_counter() - started

        hdrs = {
            k.lower(): v
            for k, v in r.getheaders()
        }

        return {
            "payload": payload,
            "status": r.status,
            "reason": r.reason,
            "length": len(data),
            "time": elapsed,
            "hash": body_sig(data),
            "json": json_shape(data),
            "location": hdrs.get("location"),
            "type": hdrs.get("content-type"),
            "body": data,
            "error": None,
        }

    except Exception as e:
        return {
            "payload": payload,
            "status": None,
            "reason": None,
            "length": 0,
            "time": time.perf_counter() - started,
            "hash": None,
            "json": None,
            "location": None,
            "type": None,
            "body": b"",
            "error": f"{type(e).__name__}: {e}",
        }

    finally:
        conn.close()


def fingerprint(r):
    if r["error"]:
        return ("ERR", r["error"].split(":", 1)[0])

    return (
        r["status"],
        r["length"],
        r["hash"],
        r["json"],
        r["location"],
    )


def score(result, common_fp, median_time):
    if result["error"]:
        return 8

    s = 0
    fp = fingerprint(result)

    if fp != common_fp:
        s += 4

    if result["status"] and result["status"] >= 500:
        s += 5

    if result["status"] in (200, 201, 202, 204):
        if common_fp[0] in (401, 403, 404):
            s += 8

    if result["location"]:
        s += 1

    if median_time and result["time"] > max(
        median_time * 3,
        median_time + 1.0,
    ):
        s += 3

    return s


def save_case(root, idx, result):
    root.mkdir(parents=True, exist_ok=True)

    stem = root / f"{idx:03d}"

    (stem.with_suffix(".payload.txt")).write_text(
        result["payload"],
        encoding="utf-8",
    )

    if result["body"]:
        stem.with_suffix(".body.bin").write_bytes(result["body"])


def default_payloads():
    return [
        "",
        "0",
        "1",
        "-1",
        "null",
        "true",
        "false",
        "undefined",
        "NaN",
        " ",
        "%00",
        "%0a",
        "%0d%0a",
        "..",
        "../",
        "../../",
        "/",
        "//",
        "///",
        ".",
        "...",
        ":",
        "::",
        "*",
        "?",
        "#",
        "%",
        "%25",
        "%252e",
        "%2e",
        "%2f",
        "%5c",
        "A" * 8,
        "A" * 64,
        "A" * 512,
        "2147483647",
        "2147483648",
        "4294967295",
        "9223372036854775807",
        "-9223372036854775808",
        "1e309",
        "[]",
        "{}",
        "[null]",
        '{"x":null}',
        '"',
        "'",
        "\\",
        "\\\\",
        "<>",
        "()",
        "${x}",
        "{{x}}",
    ]


def load_payloads(path):
    if not path:
        return default_payloads()

    values = []

    for line in Path(path).read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        if line.startswith("#"):
            continue

        values.append(line)

    return values


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("request")
    ap.add_argument("--base", required=True)
    ap.add_argument("--payloads")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--save", default="spikebench_hits")
    ap.add_argument("--show", type=int, default=20)

    args = ap.parse_args()

    req = read_request(args.request)

    if not has_marker(req):
        raise SystemExit(
            f"no {MARKER} marker found in request"
        )

    base = urlsplit(args.base)

    if base.scheme not in ("http", "https") or not base.hostname:
        raise SystemExit("bad --base")

    payloads = load_payloads(args.payloads)

    print(
        f"{req['method']} {req['target']}  "
        f"[{len(payloads)} mutations]"
    )

    results = []

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as pool:
        jobs = [
            pool.submit(
                send,
                args.base,
                req,
                payload,
                args.timeout,
            )
            for payload in payloads
        ]

        for job in as_completed(jobs):
            results.append(job.result())

    groups = {}

    for r in results:
        fp = fingerprint(r)
        groups.setdefault(fp, []).append(r)

    common_fp, common_group = max(
        groups.items(),
        key=lambda x: len(x[1]),
    )

    timings = [
        r["time"]
        for r in results
        if not r["error"]
    ]

    median_time = statistics.median(timings) if timings else 0

    print()
    print("baseline")
    print(f"  cluster : {len(common_group)}/{len(results)}")
    print(f"  status  : {common_fp[0]}")
    print(f"  length  : {common_fp[1]}")
    print(f"  hash    : {common_fp[2]}")
    print(f"  median  : {median_time:.3f}s")

    ranked = sorted(
        results,
        key=lambda x: (
            score(x, common_fp, median_time),
            x["time"],
        ),
        reverse=True,
    )

    interesting = [
        r for r in ranked
        if score(r, common_fp, median_time)
    ]

    print()
    print(f"clusters : {len(groups)}")
    print(f"outliers : {len(interesting)}")
    print()

    for i, r in enumerate(
        interesting[:args.show],
        1,
    ):
        s = score(r, common_fp, median_time)

        if r["error"]:
            print(
                f"[{s:02d}] {r['payload']!r:<22} "
                f"{r['error']}"
            )
            continue

        bits = [
            f"[{s:02d}]",
            f"{r['payload']!r:<22}",
            str(r["status"]),
            f"len={r['length']}",
            f"t={r['time']:.3f}s",
            f"h={r['hash']}",
        ]

        if r["json"]:
            bits.append(f"json={r['json']}")

        if r["location"]:
            bits.append(f"-> {r['location']}")

        print(" ".join(bits))

    if interesting:
        root = Path(args.save)

        for i, r in enumerate(interesting, 1):
            save_case(root, i, r)

        print()
        print(f"saved {len(interesting)} case(s) to {root}")


if __name__ == "__main__":
    main()
