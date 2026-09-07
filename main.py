import json
import os
import re
import shutil
import subprocess
import sys
import time
import requests
import ipaddress

RULE_DIR = "rule"
TEMP_DIR = "temp"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


def setup_dirs():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(RULE_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)


def fetch_content(url):
    sep = "&" if "?" in url else "?"
    fresh_url = f"{url}{sep}_t={int(time.time())}"
    for attempt in range(3):
        try:
            resp = requests.get(fresh_url, headers=HEADERS, timeout=20)
            if resp.status_code == 200:
                return resp.text
            else:
                print(f"[Warning] HTTP {resp.status_code} for {url}")
        except Exception as e:
            print(f"[Warning] Failed to fetch {url} (Attempt {attempt+1}): {e}")
            time.sleep(2)
    return None


def is_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def clean_domain_list(domain_iterable):
    """
    清洗规则中的垃圾/水印域名：
    过滤掉包含 skk.moe、ru1353t 等混淆/水印字符串的条目
    """
    cleaned = []
    for d in domain_iterable:
        d_str = str(d).strip()
        # 过滤包含 skk.moe / 5ukk4w 等常见水印特征的字符串
        if "skk.moe" in d_str.lower() or "5ukk4w" in d_str.lower():
            continue
        if d_str:
            cleaned.append(d_str)
    return sorted(set(cleaned))


def try_parse_as_singbox_json(content):
    stripped = content.lstrip("\ufeff").strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except Exception:
        return None
    if isinstance(data, dict) and "rules" in data:
        return data
    return None


def determine_domain_version(domain_rule):
    """
    规则版本划分：
    - 仅含有 "domain" 参数使用 "version": 1
    - 含有 domain_suffix / domain_keyword / domain_regex 等其他参数使用 "version": 2
    """
    if not domain_rule:
        return 1
    keys = set(domain_rule.keys())
    if keys == {"domain"}:
        return 1
    return 2


def split_singbox_json(data):
    domain_list, domain_suffix_list = [], []
    domain_keyword_list, domain_regex_list = [], []
    ip_cidr_list = []

    rules = data.get("rules", [])
    for r in rules:
        if not isinstance(r, dict):
            continue
        if "domain" in r:
            domain_list.extend(r["domain"] if isinstance(r["domain"], list) else [r["domain"]])
        if "domain_suffix" in r:
            domain_suffix_list.extend(r["domain_suffix"] if isinstance(r["domain_suffix"], list) else [r["domain_suffix"]])
        if "domain_keyword" in r:
            domain_keyword_list.extend(r["domain_keyword"] if isinstance(r["domain_keyword"], list) else [r["domain_keyword"]])
        if "domain_regex" in r:
            domain_regex_list.extend(r["domain_regex"] if isinstance(r["domain_regex"], list) else [r["domain_regex"]])
        if "ip_cidr" in r:
            ip_cidr_list.extend(r["ip_cidr"] if isinstance(r["ip_cidr"], list) else [r["ip_cidr"]])

    # 进行清洗与去重
    c_domain = clean_domain_list(domain_list)
    c_domain_suffix = clean_domain_list(domain_suffix_list)
    c_domain_keyword = clean_domain_list(domain_keyword_list)
    c_domain_regex = clean_domain_list(domain_regex_list)
    c_ip_cidr = sorted(set(ip_cidr_list))

    # 构建域名规则字典：如果过滤后列表为空，不添加该 key
    domain_rule = {}
    if c_domain:
        domain_rule["domain"] = c_domain
    if c_domain_suffix:
        domain_rule["domain_suffix"] = c_domain_suffix
    if c_domain_keyword:
        domain_rule["domain_keyword"] = c_domain_keyword
    if c_domain_regex:
        domain_rule["domain_regex"] = c_domain_regex

    # 只有当 domain_rule 不为空时才生成对应的 json 对象，否则保持为 None
    domain_json_data = None
    if domain_rule:
        v = determine_domain_version(domain_rule)
        domain_json_data = {"version": v, "rules": [domain_rule]}

    ip_json_data = None
    if c_ip_cidr:
        ip_json_data = {"version": 1, "rules": [{"ip_cidr": c_ip_cidr}]}

    return domain_json_data, ip_json_data


def parse_to_singbox_json_split(content):
    content_str = content.strip()
    domain_list, domain_suffix_list = [], []
    domain_keyword_list, domain_regex_list = [], []
    ip_cidr_list = []

    for line in content_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("payload:"):
            continue
        line = re.sub(r"^[-'\"]+\s*", "", line).rstrip("',\"")

        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            rule_type = parts[0].upper()
            target = parts[1] if len(parts) > 1 else ""
            if target:
                if rule_type in ["DOMAIN-SUFFIX", "HOST-SUFFIX"]:
                    domain_suffix_list.append(target)
                elif rule_type in ["DOMAIN", "HOST"]:
                    domain_list.append(target)
                elif rule_type in ["DOMAIN-KEYWORD", "HOST-KEYWORD"]:
                    domain_keyword_list.append(target)
                elif rule_type in ["DOMAIN-REGEX", "HOST-REGEX"]:
                    domain_regex_list.append(target)
                elif rule_type in ["IP-CIDR", "IP6-CIDR", "IP-CIDR6"]:
                    ip_cidr_list.append(target)
            continue

        if line.startswith("full:"):
            domain_list.append(line[5:])
        elif line.startswith("domain:"):
            domain_suffix_list.append(line[7:])
        elif line.startswith("keyword:"):
            domain_keyword_list.append(line[8:])
        elif line.startswith("regexp:"):
            domain_regex_list.append(line[7:])
        elif line.startswith("+."):
            domain_suffix_list.append(line[2:])
        elif line.startswith("."):
            domain_suffix_list.append(line[1:])
        elif is_cidr(line):
            ip_cidr_list.append(line)
        else:
            domain_suffix_list.append(line)

    c_domain = clean_domain_list(domain_list)
    c_domain_suffix = clean_domain_list(domain_suffix_list)
    c_domain_keyword = clean_domain_list(domain_keyword_list)
    c_domain_regex = clean_domain_list(domain_regex_list)
    c_ip_cidr = sorted(set(ip_cidr_list))

    domain_rule = {}
    if c_domain:
        domain_rule["domain"] = c_domain
    if c_domain_suffix:
        domain_rule["domain_suffix"] = c_domain_suffix
    if c_domain_keyword:
        domain_rule["domain_keyword"] = c_domain_keyword
    if c_domain_regex:
        domain_rule["domain_regex"] = c_domain_regex

    domain_json_data = None
    if domain_rule:
        v = determine_domain_version(domain_rule)
        domain_json_data = {"version": v, "rules": [domain_rule]}

    ip_json_data = None
    if c_ip_cidr:
        ip_json_data = {"version": 1, "rules": [{"ip_cidr": c_ip_cidr}]}

    return domain_json_data, ip_json_data


def compile_srs(json_path, srs_path, label):
    cmd = ["sing-box", "rule-set", "compile", json_path, "-o", srs_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"  [Success] Compiled: {os.path.basename(srs_path)}")
            return True
        print(f"  [Error] sing-box compile failed for {label}: {res.stderr.strip()}")
        return False
    except Exception as e:
        print(f"  [Exception] Failed to run sing-box for {label}: {e}")
        return False


def compile_rule(rule_name, json_data):
    if not json_data:
        return False

    temp_json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    final_json_path = os.path.join(RULE_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    with open(final_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)
    with open(temp_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    return compile_srs(temp_json_path, srs_path, rule_name)


def derive_rule_name(url):
    base = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.(ya?ml|list|txt|conf|json)$", "", base, flags=re.IGNORECASE)


def process_links():
    if not os.path.exists("links.txt"):
        print("[Error] links.txt not found!")
        sys.exit(1)

    with open("links.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    success_count = 0
    fail_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "," in line and line.split(",", 1)[1].strip().startswith(("http://", "https://")):
            rule_name, url = (p.strip() for p in line.split(",", 1))
        else:
            url = line
            rule_name = derive_rule_name(url)

        if not rule_name or not url:
            print(f"[Skip] Invalid line: {line}")
            continue

        print(f"\n[Processing] {rule_name} from {url}")
        content = fetch_content(url)
        if not content:
            print(f"[Skip] Failed to fetch content for {rule_name}")
            fail_count += 1
            continue

        try:
            singbox_data = try_parse_as_singbox_json(content)
            if singbox_data is not None:
                domain_json, ip_json = split_singbox_json(singbox_data)
            else:
                domain_json, ip_json = parse_to_singbox_json_split(content)

            processed_any = False

            if domain_json and compile_rule(rule_name, domain_json):
                processed_any = True

            if ip_json and compile_rule(f"{rule_name}-ip", ip_json):
                processed_any = True

            if processed_any:
                success_count += 1
            else:
                print(f"  [Warning] No valid rules after filtering in {rule_name}")
                fail_count += 1

        except Exception as e:
            print(f"[Error] Exception in parsing {rule_name}: {e}")
            fail_count += 1

    print(f"\nFinished processing. Success: {success_count}, Failed: {fail_count}")
    if success_count == 0:
        print("[Fatal] 没有任何规则被成功编译，判定本次同步失败。")
        sys.exit(1)


if __name__ == "__main__":
    setup_dirs()
    process_links()
