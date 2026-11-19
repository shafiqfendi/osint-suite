import hashlib
import io
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import dns.resolver
import requests
import whois
from flask import Flask, jsonify, render_template, request
from PIL import ExifTags, Image

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # Had muat naik gambar 10MB

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}


def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    return raw.split("/")[0].split(":")[0]


@app.route("/")
def index():
    return render_template("index.html")


# ==========================================
# 1. DOMAIN RECON (DNS, WHOIS, SSL, HEADERS, SUBDOMAINS)
# ==========================================
@app.route("/api/domain", methods=["POST"])
def api_domain():
    data = request.get_json(silent=True) or {}
    domain = clean_domain(data.get("target", ""))
    if not domain or "." not in domain:
        return jsonify({"error": "Sila masukkan domain yang sah (cth: example.com)"}), 400

    result = {
        "target": domain,
        "ip": None,
        "dns": {},
        "whois": {},
        "ssl": {},
        "http_headers": {},
        "subdomains": [],
    }

    # Resolve IP utama
    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception:
        result["ip"] = "Tidak ditemui"

    # DNS Records
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, rtype)
            result["dns"][rtype] = [r.to_text() for r in answers]
        except Exception:
            result["dns"][rtype] = []

    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        def fmt_date(d):
            if isinstance(d, list):
                d = d[0]
            return d.strftime("%Y-%m-%d %H:%M:%S") if isinstance(d, datetime) else str(d)

        result["whois"] = {
            "registrar": w.registrar,
            "creation_date": fmt_date(w.creation_date) if w.creation_date else "-",
            "expiration_date": fmt_date(w.expiration_date) if w.expiration_date else "-",
            "org": w.org or "-",
            "country": w.country or "-",
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
    except Exception as e:
        result["whois"] = {"error": f"WHOIS gagal ditarik: {str(e)}"}

    # SSL Certificate Inspection
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                result["ssl"] = {
                    "common_name": subject.get("commonName", "-"),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "-")),
                    "valid_from": cert.get("notBefore", "-"),
                    "valid_until": cert.get("notAfter", "-"),
                    "san_count": len(cert.get("subjectAltName", [])),
                }
    except Exception as e:
        result["ssl"] = {"error": f"Tiada SSL atau sambungan port 443 gagal ({str(e)})"}

    # HTTP Headers & Security Check
    try:
        resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=5, allow_redirects=True)
        h = resp.headers
        result["http_headers"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "server": h.get("Server", "Disembunyikan"),
            "powered_by": h.get("X-Powered-By", "-"),
            "hsts": "Ada" if "Strict-Transport-Security" in h else "Tiada",
            "csp": "Ada" if "Content-Security-Policy" in h else "Tiada",
            "x_frame_options": h.get("X-Frame-Options", "Tiada"),
        }
    except Exception as e:
        result["http_headers"] = {"error": f"Gagal capai HTTP/HTTPS: {str(e)}"}

    # Passive Subdomains via crt.sh
    try:
        crt_resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", headers=HEADERS, timeout=8
        )
        if crt_resp.status_code == 200:
            subs = set()
            for entry in crt_resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
            result["subdomains"] = sorted(list(subs))[:60]  # Hadkan 60 teratas
    except Exception:
        result["subdomains"] = []

    return jsonify(result)


# ==========================================
# 2. IP GEOLOCATION, REVERSE DNS & PORT CHECK
# ==========================================
def check_port(ip: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None


@app.route("/api/ip", methods=["POST"])
def api_ip():
    data = request.get_json(silent=True) or {}
    target = clean_domain(data.get("target", ""))
    if not target:
        return jsonify({"error": "Sila masukkan IP atau domain"}), 400

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return jsonify({"error": "Gagal resolve IP bagi sasaran tersebut"}), 400

    geo = {}
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        geo = r.json()
    except Exception as e:
        geo = {"success": False, "message": str(e)}

    try:
        rev_dns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rev_dns = "Tiada rekod PTR"

    common_ports = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    open_ports = []
    with ThreadPoolExecutor(max_workers=13) as ex:
        futures = {ex.submit(check_port, ip, p): p for p in common_ports}
        for fut in as_completed(futures):
            res_port = fut.result()
            if res_port:
                open_ports.append({"port": res_port, "service": common_ports[res_port]})

    open_ports.sort(key=lambda x: x["port"])

    return jsonify({
        "input": target,
        "ip": ip,
        "reverse_dns": rev_dns,
        "geo": geo,
        "open_ports": open_ports,
    })


# ==========================================
# 3. USERNAME SCANNER (MINI-SHERLOCK)
# ==========================================
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{u}", "check_url": "https://api.github.com/users/{u}"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "check_url": "https://gitlab.com/api/v4/users?username={u}", "json_non_empty": True},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "check_url": "https://www.reddit.com/user/{u}/about.json"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "check_url": "https://dev.to/api/users/by_username?url={u}"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={u}", "check_url": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "not_null": True},
    {"name": "Telegram", "url": "https://t.me/{u}", "check_url": "https://t.me/{u}", "must_contain": "tgme_page_title"},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "check_url": "https://linktr.ee/{u}"},
    {"name": "Medium", "url": "https://medium.com/@{u}", "check_url": "https://medium.com/@{u}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "check_url": "https://www.pinterest.com/{u}/"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{u}", "check_url": "https://pastebin.com/u/{u}"},
    {"name": "Wikipedia", "url": "https://en.wikipedia.org/wiki/User:{u}", "check_url": "https://en.wikipedia.org/wiki/User:{u}"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={u}", "check_url": "https://www.roblox.com/user.aspx?username={u}"},
]


def probe_platform(p, username):
    url = p["url"].format(u=username)
    check_url = p["check_url"].format(u=username)
    status = "Tidak Ditemui"
    found = False
    try:
        r = requests.get(check_url, headers=HEADERS, timeout=4, allow_redirects=True)
        if p.get("json_non_empty"):
            if r.status_code == 200 and len(r.json()) > 0:
                found = True
        elif p.get("not_null"):
            if r.status_code == 200 and r.text.strip() != "null":
                found = True
        elif p.get("must_contain"):
            if r.status_code == 200 and p["must_contain"] in r.text:
                found = True
        else:
            if r.status_code == 200:
                found = True
            elif r.status_code in (403, 429):
                status = "Disekat (Semak Manual)"
        if found:
            status = "Ditemui"
    except Exception:
        status = "Timeout (Semak Manual)"

    return {"platform": p["name"], "url": url, "found": found, "status": status}


@app.route("/api/username", methods=["POST"])
def api_username():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lstrip("@")
    if not username or not re.match(r"^[a-zA-Z0-9._-]{2,40}$", username):
        return jsonify({"error": "Username tidak sah"}), 400

    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(probe_platform, p, username) for p in PLATFORMS]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: (not x["found"], x["platform"]))
    return jsonify({"username": username, "results": results})


# ==========================================
# 4. EMAIL INTELLIGENCE
# ==========================================
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com"
}


@app.route("/api/email", methods=["POST"])
def api_email():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Format emel tidak sah"}), 400

    domain = email.split("@")[1]
    mx_records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        mx_records = [r.to_text() for r in resolver.resolve(domain, "MX")]
    except Exception:
        pass

    md5_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?s=200&d=404"
    has_gravatar = False
    try:
        g_resp = requests.get(gravatar_url, timeout=4)
        has_gravatar = g_resp.status_code == 200
    except Exception:
        pass

    return jsonify({
        "email": email,
        "domain": domain,
        "is_disposable": domain in DISPOSABLE_DOMAINS,
        "mx_valid": len(mx_records) > 0,
        "mx_records": mx_records,
        "gravatar_found": has_gravatar,
        "gravatar_url": gravatar_url if has_gravatar else None,
        "md5_hash": md5_hash,
    })


# ==========================================
# 5. IMAGE EXIF & GPS METADATA EXTRACTOR
# ==========================================
def to_degrees(value):
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)


@app.route("/api/exif", methods=["POST"])
def api_exif():
    if "image" not in request.files:
        return jsonify({"error": "Tiada fail gambar dimuat naik"}), 400

    file = request.files["image"]
    try:
        img = Image.open(io.BytesIO(file.read()))
        info = {
            "filename": file.filename,
            "format": img.format,
            "mode": img.mode,
            "size": f"{img.width} x {img.height} px",
            "metadata": {},
            "gps": None,
        }

        exif_data = img.getexif()
        if exif_data:
            for tag_id, val in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                if isinstance(val, bytes):
                    val = val.decode(errors="ignore")[:100]
                info["metadata"][tag] = str(val)

            # Tarik IFD GPS (tag 34853)
            gps_ifd = exif_data.get_ifd(0x8825)
            if gps_ifd:
                gps_parsed = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
                if "GPSLatitude" in gps_parsed and "GPSLongitude" in gps_parsed:
                    lat = to_degrees(gps_parsed["GPSLatitude"])
                    if gps_parsed.get("GPSLatitudeRef") == "S":
                        lat = -lat
                    lon = to_degrees(gps_parsed["GPSLongitude"])
                    if gps_parsed.get("GPSLongitudeRef") == "W":
                        lon = -lon
                    info["gps"] = {
                        "latitude": round(lat, 6),
                        "longitude": round(lon, 6),
                        "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                    }

        return jsonify(info)
    except Exception as e:
        return jsonify({"error": f"Gagal membaca gambar: {str(e)}"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)