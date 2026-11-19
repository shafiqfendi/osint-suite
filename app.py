import hashlib
import io
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import dns.resolver
import phonenumbers
import requests
import whois
from flask import Flask, jsonify, render_template, request
from phonenumbers import carrier, geocoder, timezone
from PIL import ExifTags, Image

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # Had 12MB

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
}


def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    return raw.split("/")[0].split(":")[0]


@app.route("/")
def index():
    return render_template("index.html")


# =========================================================
# 1. DOMAIN RECON v2 (DNS, SPF/DMARC, WHOIS, SSL, TECH, ROBOTS, SUBDOMAINS)
# =========================================================
def detect_tech_stack(headers, html):
    tech = set()
    h_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    html_low = html.lower()[:30000]

    signatures = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "LiteSpeed": ["litespeed"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Shopify": ["cdn.shopify.com", "shopify"],
        "Next.js": ["_next/static", "__next_data__"],
        "React": ["react-root", "data-reactroot"],
        "Vue.js": ["data-v-", "vue.js"],
        "Laravel": ["laravel_session", "xsrf-token"],
        "PHP": ["x-powered-by:php", "phpsessid"],
        "ASP.NET": ["asp.net", "x-aspnet-version"],
        "Google Analytics / GTM": ["googletagmanager.com", "gtag("],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.css"],
        "Tailwind CSS": ["tailwindcss", "tw-"],
    }
    for name, keys in signatures.items():
        if any(k in h_str or k in html_low for k in keys):
            tech.add(name)
    return sorted(list(tech))


@app.route("/api/domain", methods=["POST"])
def api_domain():
    data = request.get_json(silent=True) or {}
    domain = clean_domain(data.get("target", ""))
    if not domain or "." not in domain:
        return jsonify({"error": "Sila masukkan domain yang sah (cth: example.com)"}), 400

    result = {
        "target": domain,
        "ip": "Tidak ditemui",
        "dns": {},
        "email_security": {"spf": "Tiada", "dmarc": "Tiada"},
        "whois": {},
        "ssl": {},
        "http": {},
        "tech_stack": [],
        "robots_disallow": [],
        "subdomains": [],
    }

    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception:
        pass

    # DNS Records + CAA
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [r.to_text().strip('"') for r in answers]
            result["dns"][rtype] = records
            if rtype == "TXT":
                for rec in records:
                    if rec.lower().startswith("v=spf1"):
                        result["email_security"]["spf"] = rec
        except Exception:
            result["dns"][rtype] = []

    # DMARC Check
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_ans:
            txt = r.to_text().strip('"')
            if "v=dmarc1" in txt.lower():
                result["email_security"]["dmarc"] = txt
    except Exception:
        pass

    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        def fmt(d):
            if isinstance(d, list):
                d = d[0]
            return d.strftime("%Y-%m-%d") if isinstance(d, datetime) else str(d)

        result["whois"] = {
            "registrar": w.registrar or "-",
            "creation_date": fmt(w.creation_date) if w.creation_date else "-",
            "expiration_date": fmt(w.expiration_date) if w.expiration_date else "-",
            "org": w.org or "-",
            "country": w.country or "-",
            "emails": list(set(w.emails)) if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
    except Exception as e:
        result["whois"] = {"error": f"WHOIS terhad/gagal: {str(e)[:120]}"}

    # SSL Inspection
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                result["ssl"] = {
                    "common_name": subject.get("commonName", "-"),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "-")),
                    "valid_from": cert.get("notBefore", "-"),
                    "valid_until": cert.get("notAfter", "-"),
                    "san_sample": sans[:15],
                    "san_count": len(sans),
                }
    except Exception as e:
        result["ssl"] = {"error": f"Tiada SSL / Port 443 gagal ({str(e)[:80]})"}

    # HTTP Headers, Title & Tech Stack
    try:
        resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=6, allow_redirects=True)
        h = resp.headers
        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else "-"
        result["http"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "title": title,
            "server": h.get("Server", "Disembunyikan"),
            "powered_by": h.get("X-Powered-By", "-"),
            "hsts": "Ada" if "Strict-Transport-Security" in h else "Tiada",
            "csp": "Ada" if "Content-Security-Policy" in h else "Tiada",
            "x_frame": h.get("X-Frame-Options", "Tiada"),
        }
        result["tech_stack"] = detect_tech_stack(h, resp.text)
    except Exception as e:
        result["http"] = {"error": f"Gagal capai HTTPS: {str(e)[:90]}"}

    # robots.txt Inspector
    try:
        r_rob = requests.get(f"https://{domain}/robots.txt", headers=HEADERS, timeout=4)
        if r_rob.status_code == 200 and "disallow" in r_rob.text.lower():
            disallows = []
            for line in r_rob.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallows.append(path)
            result["robots_disallow"] = sorted(list(set(disallows)))[:30]
    except Exception:
        pass

    # Multi-Source Passive Subdomains (crt.sh + HackerTarget)
    subs = set()
    try:
        crt = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=HEADERS, timeout=7)
        if crt.status_code == 200:
            for entry in crt.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
    except Exception:
        pass

    try:
        ht = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers=HEADERS, timeout=6)
        if ht.status_code == 200 and "error" not in ht.text.lower():
            for line in ht.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain):
                    subs.add(host)
    except Exception:
        pass

    result["subdomains"] = sorted(list(subs))[:80]
    return jsonify(result)


# =========================================================
# 2. IP & NETWORK v2 (SHODAN INTERNETDB + GEO + BANNER PORT SCAN)
# =========================================================
def scan_port_banner(ip: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            if s.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    if port in (80, 8080):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(120).decode(errors="ignore").strip().splitlines()[0][:70]
                except Exception:
                    pass
                return {"port": port, "banner": banner}
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

    # Geolocation + Proxy/Hosting info via ip-api.com (fallback ipwho.is)
    geo = {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting",
            timeout=5,
        ).json()
        if r.get("status") == "success":
            geo = r
    except Exception:
        pass

    # Shodan InternetDB (Free, No Key - Ports, CVEs, CPEs, Hostnames, Tags)
    shodan = {}
    try:
        sr = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if sr.status_code == 200:
            shodan = sr.json()
    except Exception:
        pass

    try:
        rev_dns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rev_dns = "Tiada rekod PTR"

    common_ports = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    open_ports = []
    with ThreadPoolExecutor(max_workers=14) as ex:
        futures = {ex.submit(scan_port_banner, ip, p): p for p in common_ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                res["service"] = common_ports[res["port"]]
                open_ports.append(res)
    open_ports.sort(key=lambda x: x["port"])

    return jsonify({
        "input": target,
        "ip": ip,
        "reverse_dns": rev_dns,
        "geo": geo,
        "shodan": shodan,
        "open_ports": open_ports,
    })


# =========================================================
# 3. USERNAME SCANNER v2 (18 PLATFORM + SEMAKAN API TEPAT)
# =========================================================
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{u}", "check": "https://api.github.com/users/{u}", "mode": "github"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "check": "https://gitlab.com/api/v4/users?username={u}", "mode": "json_list"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "check": "https://www.reddit.com/user/{u}/about.json", "mode": "reddit"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "check": "https://dev.to/api/users/by_username?url={u}", "mode": "status200"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={u}", "check": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "mode": "not_null"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "check": "https://api.chess.com/pub/player/{u}", "mode": "status200"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "check": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "mode": "keybase"},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{u}", "check": "https://hub.docker.com/v2/users/{u}/", "mode": "status200"},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "check": "https://pypi.org/user/{u}/", "mode": "status200"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "check": "https://www.npmjs.com/~{u}", "mode": "status200"},
    {"name": "Telegram", "url": "https://t.me/{u}", "check": "https://t.me/{u}", "mode": "contains", "needle": "tgme_page_title"},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "check": "https://linktr.ee/{u}", "mode": "status200"},
    {"name": "Medium", "url": "https://medium.com/@{u}", "check": "https://medium.com/@{u}", "mode": "status200"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "check": "https://www.pinterest.com/{u}/", "mode": "status200"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{u}", "check": "https://pastebin.com/u/{u}", "mode": "status200"},
    {"name": "Wikipedia", "url": "https://en.wikipedia.org/wiki/User:{u}", "check": "https://en.wikipedia.org/wiki/User:{u}", "mode": "status200"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={u}", "check": "https://www.roblox.com/user.aspx?username={u}", "mode": "status200"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "check": "https://steamcommunity.com/id/{u}", "mode": "not_contains", "needle": "The specified profile could not be found"},
]


def probe_user(p, username):
    url = p["url"].format(u=username)
    check = p["check"].format(u=username)
    found, status, extra = False, "Tidak Ditemui", ""
    try:
        r = requests.get(check, headers=HEADERS, timeout=4.5, allow_redirects=True)
        mode = p["mode"]
        if mode == "github" and r.status_code == 200:
            j = r.json()
            found = True
            extra = f"{j.get('name') or j.get('login')} | {j.get('public_repos',0)} repos | {j.get('location') or '-'}"
        elif mode == "reddit" and r.status_code == 200:
            j = r.json().get("data", {})
            if j.get("name"):
                found = True
                extra = f"Karma: {j.get('total_karma', 0)}"
        elif mode == "json_list" and r.status_code == 200 and len(r.json()) > 0:
            found = True
        elif mode == "not_null" and r.status_code == 200 and r.text.strip() != "null":
            found = True
        elif mode == "keybase" and r.status_code == 200:
            them = r.json().get("them") or []
            if them and them[0] is not None:
                found = True
        elif mode == "contains" and r.status_code == 200 and p["needle"] in r.text:
            found = True
        elif mode == "not_contains" and r.status_code == 200 and p["needle"] not in r.text:
            found = True
        elif mode == "status200":
            if r.status_code == 200:
                found = True
            elif r.status_code in (403, 429):
                status = "Disekat (Semak Manual)"

        if found:
            status = "Ditemui"
    except Exception:
        status = "Timeout (Semak Manual)"

    return {"platform": p["name"], "url": url, "found": found, "status": status, "extra": extra}


@app.route("/api/username", methods=["POST"])
def api_username():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lstrip("@")
    if not username or not re.match(r"^[a-zA-Z0-9._-]{2,40}$", username):
        return jsonify({"error": "Username tidak sah"}), 400

    results = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(probe_user, p, username) for p in PLATFORMS]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: (not x["found"], x["platform"]))
    return jsonify({"username": username, "found_count": sum(1 for r in results if r["found"]), "results": results})


# =========================================================
# 4. PHONE NUMBER INTELLIGENCE (BARU!)
# =========================================================
@app.route("/api/phone", methods=["POST"])
def api_phone():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone", "").strip()
    region = data.get("region", "MY").strip().upper() or "MY"
    if not raw:
        return jsonify({"error": "Sila masukkan nombor telefon"}), 400

    try:
        parsed = phonenumbers.parse(raw, region)
        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        num_type_map = {
            0: "Talian Tetap (Fixed Line)", 1: "Mudah Alih (Mobile)",
            2: "Tetap / Mudah Alih", 3: "Bebas Tol (Toll Free)",
            4: "Kadar Premium", 6: "VoIP", 10: "Tidak Diketahui"
        }
        ntype = num_type_map.get(phonenumbers.number_type(parsed), "Lain-lain")
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        digits = e164.lstrip("+")

        return jsonify({
            "input": raw,
            "valid": is_valid,
            "possible": is_possible,
            "e164": e164,
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code": f"+{parsed.country_code}",
            "location": geocoder.description_for_number(parsed, "en") or "-",
            "carrier": carrier.name_for_number(parsed, "en") or "Tidak dikenal pasti",
            "line_type": ntype,
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "digits": digits,
        })
    except Exception as e:
        return jsonify({"error": f"Nombor tidak sah: {str(e)}"}), 400


# =========================================================
# 5. EMAIL INTELLIGENCE v2 (MX, GRAVATAR JSON, GITHUB CHECK)
# =========================================================
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "tempmail.com",
    "dispostable.com", "maildrop.cc", "fakeinbox.com", "throwawaymail.com"
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
    gravatar_img = f"https://www.gravatar.com/avatar/{md5_hash}?s=200&d=404"
    gravatar_profile = None
    has_gravatar = False

    try:
        g_json = requests.get(f"https://en.gravatar.com/{md5_hash}.json", headers=HEADERS, timeout=4)
        if g_json.status_code == 200:
            entry = g_json.json().get("entry", [{}])[0]
            has_gravatar = True
            gravatar_profile = {
                "display_name": entry.get("displayName", "-"),
                "username": entry.get("preferredUsername", "-"),
                "about": entry.get("aboutMe", "-"),
                "location": entry.get("currentLocation", "-"),
                "profile_url": entry.get("profileUrl", ""),
            }
        else:
            if requests.get(gravatar_img, timeout=3).status_code == 200:
                has_gravatar = True
    except Exception:
        pass

    # Semak sama ada emel terikat dengan akaun GitHub awam
    github_account = None
    try:
        gh = requests.get(f"https://api.github.com/search/users?q={email}+in:email", headers=HEADERS, timeout=4)
        if gh.status_code == 200 and gh.json().get("total_count", 0) > 0:
            u = gh.json()["items"][0]
            github_account = {"login": u["login"], "url": u["html_url"]}
    except Exception:
        pass

    return jsonify({
        "email": email,
        "domain": domain,
        "is_disposable": domain in DISPOSABLE,
        "mx_valid": len(mx_records) > 0,
        "mx_records": mx_records,
        "gravatar_found": has_gravatar,
        "gravatar_url": gravatar_img if has_gravatar else None,
        "gravatar_profile": gravatar_profile,
        "github_account": github_account,
        "md5_hash": md5_hash,
    })


# =========================================================
# 6. IMAGE EXIF & FILE FORENSICS v2 (FULL EXIF IFD + HASHES)
# =========================================================
def to_degrees(value):
    return float(value[0]) + (float(value[1]) / 60.0) + (float(value[2]) / 3600.0)


@app.route("/api/exif", methods=["POST"])
def api_exif():
    if "image" not in request.files:
        return jsonify({"error": "Tiada fail gambar dimuat naik"}), 400

    file = request.files["image"]
    raw_bytes = file.read()
    hashes = {
        "md5": hashlib.md5(raw_bytes).hexdigest(),
        "sha1": hashlib.sha1(raw_bytes).hexdigest(),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }

    try:
        img = Image.open(io.BytesIO(raw_bytes))
        info = {
            "filename": file.filename,
            "size_kb": round(len(raw_bytes) / 1024, 2),
            "format": img.format,
            "mode": img.mode,
            "dimensions": f"{img.width} x {img.height} px",
            "hashes": hashes,
            "metadata": {},
            "gps": None,
        }

        exif_data = img.getexif()
        if exif_data:
            # IFD0 (Kamera, Model, Perisian)
            for tag_id, val in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                if isinstance(val, bytes):
                    val = val.decode(errors="ignore")[:100]
                info["metadata"][tag] = str(val)

            # ExifIFD 0x8769 (Tarikh asal, ISO, Lens, Shutter)
            exif_ifd = exif_data.get_ifd(0x8769)
            if exif_ifd:
                for tag_id, val in exif_ifd.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if isinstance(val, bytes):
                        val = val.decode(errors="ignore")[:100]
                    info["metadata"][tag] = str(val)

            # GPS IFD 0x8825
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