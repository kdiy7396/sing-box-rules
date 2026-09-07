import json
import os
import re
import shutil
import subprocess
import sys
import ipaddress

TARGET_DIR = "App_Privacy_Report"
TEMP_DIR = "temp_app_privacy"


def setup_dirs():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)


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


def compile_and_save_rule(rule_name, rules_list):
    """
    需求5：将 rules 列表构建为 version 2 的 sing-box JSON 结构落盘并编译。
    """
    json_data = {
        "version": 2,
        "rules": rules_list
    }

    final_json_path = os.path.join(TARGET_DIR, f"{rule_name}.json")
    temp_json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    srs_path = os.path.join(TARGET_DIR, f"{rule_name}.srs")

    with open(final_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)
    with open(temp_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    return compile_srs(temp_json_path, srs_path, rule_name)


def process_json_file(file_path):
    base_name = os.path.basename(file_path)
    rule_name = re.sub(r"\.json$", "", base_name, flags=re.IGNORECASE)

    # 1. 情况一：如果是独立存在的 -ip.json，仅直通编译生成 -ip.srs
    if base_name.endswith("-ip.json"):
        print(f"\n[Compiling Standalone IP Rule] {base_name}")
        srs_path = os.path.join(TARGET_DIR, f"{rule_name}.srs")
        return compile_srs(file_path, srs_path, rule_name)

    # 2. 情况二：源主文件，执行拆分逻辑
    print(f"\n[Processing App Privacy File] {base_name}")

    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [Error] Failed to parse JSON file {file_path}: {e}")
        return False

    if not isinstance(data, dict) or "rules" not in data:
        print(f"  [Skip] Invalid sing-box JSON structure in {file_path}")
        return False

    domain_list, domain_suffix_list = [], []
    domain_keyword_list, domain_regex_list = [], []
    ip_cidr_list = []

    # 提取规则字段
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

    domain_rule = {}
    if domain_list:
        domain_rule["domain"] = sorted(set(domain_list))
    if domain_suffix_list:
        domain_rule["domain_suffix"] = sorted(set(domain_suffix_list))
    if domain_keyword_list:
        domain_rule["domain_keyword"] = sorted(set(domain_keyword_list))
    if domain_regex_list:
        domain_rule["domain_regex"] = sorted(set(domain_regex_list))

    ip_cidr_list = sorted(set(ip_cidr_list))
    processed_any = False

    # 输出/更新域名规则 (Name.json 与 Name.srs，需求5强制 version 2)
    if domain_rule:
        if compile_and_save_rule(rule_name, [domain_rule]):
            processed_any = True

    # 输出/更新 IP 规则 (Name-ip.json 与 Name-ip.srs，需求5强制 version 2)
    if ip_cidr_list:
        ip_rule_name = f"{rule_name}-ip"
        if compile_and_save_rule(ip_rule_name, [{"ip_cidr": ip_cidr_list}]):
            processed_any = True

    return processed_any


def main():
    setup_dirs()

    if not os.path.exists(TARGET_DIR):
        print(f"[Error] Directory '{TARGET_DIR}' does not exist!")
        sys.exit(1)

    json_files = [f for f in os.listdir(TARGET_DIR) if f.endswith(".json")]
    if not json_files:
        print(f"[Warning] No JSON files found in {TARGET_DIR}")
        return

    # 优先排在前面的非 -ip 文件，确保先拆分再补充编译
    json_files.sort(key=lambda x: 1 if x.endswith("-ip.json") else 0)

    success_count = 0
    fail_count = 0

    for file_name in json_files:
        file_path = os.path.join(TARGET_DIR, file_name)
        if process_json_file(file_path):
            success_count += 1
        else:
            fail_count += 1

    print(f"\n[App Privacy Report] Finished processing. Success: {success_count}, Failed/Skipped: {fail_count}")

    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)


if __name__ == "__main__":
    main()
