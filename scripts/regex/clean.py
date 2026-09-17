# #!/usr/bin/env python3
# """
# Relocate/split miscategorized vendor patterns in regex_v2.py, based on
# audited contamination in FINGERPRINTING_ADVANCED, ID_SOLUTIONS_AND_EXCHANGES,
# UX_AND_PERFORMANCE_ANALYTICS, and SECURITY_AND_BOT_MITIGATION.

# Usage: python3 relocate_categories.py regex_v2.py regex_v3.py
# """
# import re, sys

# def slug(vendor):
#     return re.sub(r'[^a-z0-9]+', '_', vendor.lower()).strip('_')

# # --- Whole-entry moves: (vendor, source_category, target_category) ---
# MOVES = [
#     ("Salesforce", "FINGERPRINTING_ADVANCED", "APP_STATE_STORAGE"),
#     ("Awin", "FINGERPRINTING_ADVANCED", "IDENTITY_TRACKING"),
#     ("Baidu", "FINGERPRINTING_ADVANCED", None),          # duplicate, delete
#     ("CHEQ", "FINGERPRINTING_ADVANCED", "SECURITY_AND_BOT_MITIGATION"),
#     ("LeadInfo", "FINGERPRINTING_ADVANCED", "ID_SOLUTIONS_AND_EXCHANGES"),
#     ("MercadoLibre", "FINGERPRINTING_ADVANCED", "IDENTITY_TRACKING"),
#     ("Stripe", "FINGERPRINTING_ADVANCED", "SECURITY_AND_BOT_MITIGATION"),
#     ("Tapad", "FINGERPRINTING_ADVANCED", "ID_SOLUTIONS_AND_EXCHANGES"),
#     ("Teads", "FINGERPRINTING_ADVANCED", "ID_SOLUTIONS_AND_EXCHANGES"),
#     ("Yandex", "FINGERPRINTING_ADVANCED", "IDENTITY_TRACKING"),
#     ("Auth0", "SECURITY_AND_BOT_MITIGATION", "TECHNICAL_PASSWORDS"),
#     # Microsoft / Oracle / Itch require manual split below, not moved whole.
# ]

# # --- Token-level splits: (vendor, source_category, [tokens], target_category, new_key_suffix) ---
# SPLITS = [
#     ("Zoho", "UX_AND_PERFORMANCE_ANALYTICS", ["ZCAMPAIGN_CSRF_TOKEN"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("Zoho", "UX_AND_PERFORMANCE_ANALYTICS", ["zc_consent"], "CONSENT_AND_PRIVACY", "consent"),
#     ("TrustPilot", "ID_SOLUTIONS_AND_EXCHANGES", ["csrf\\-canary"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("TrustPilot", "ID_SOLUTIONS_AND_EXCHANGES", ["amplitude_id"], None, None),  # duplicate, delete only
#     ("Yandex.Metrica", "UX_AND_PERFORMANCE_ANALYTICS", ["is_gdpr_b", "is_gdpr"], "CONSENT_AND_PRIVACY", "consent"),
#     ("Dynatrace", "UX_AND_PERFORMANCE_ANALYTICS", ["ssoCSRFCookie"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("Shopify", "UX_AND_PERFORMANCE_ANALYTICS", ["_tracking_consent"], "CONSENT_AND_PRIVACY", "consent"),
#     ("X", "ID_SOLUTIONS_AND_EXCHANGES", ["csrf_same_site", "csrf_same_site_set"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("SAP", "ID_SOLUTIONS_AND_EXCHANGES", ["_gig_email"], "DIRECT_PII_KEYS", "email"),
#     ("Hubspot", "ID_SOLUTIONS_AND_EXCHANGES", ["hs\\-membership\\-csrf", "hubspotapi\\-csrf"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("Indeed", "UX_AND_PERFORMANCE_ANALYTICS", ["INDEED_CSRF_TOKEN"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("Kentico", "UX_AND_PERFORMANCE_ANALYTICS", ["CMSCsrfCookie"], "SECURITY_AND_BOT_MITIGATION", "csrf"),
#     ("ABlyft", "UX_AND_PERFORMANCE_ANALYTICS", ["ablyft_tracking_consent"], "CONSENT_AND_PRIVACY", "consent"),
#     ("Media.net", "ID_SOLUTIONS_AND_EXCHANGES", ["gdpr_status"], "CONSENT_AND_PRIVACY", "consent"),
# ]

# def find_entry(lines, category, vendor_key):
#     """Return (start, end, indent, regex_body) for a category's dict line matching vendor_key."""
#     cat_re = re.compile(rf"^\s*'{category}'\s*:\s*\{{")
#     entry_re = re.compile(r"^(\s*)'(" + re.escape(vendor_key) + r"[a-z0-9_]*)'\s*:\s*r'((?:[^'\\]|\\.)*)'")
#     in_cat, depth = False, 0
#     for i, line in enumerate(lines):
#         if cat_re.match(line):
#             in_cat, depth = True, line.count('{') - line.count('}')
#             continue
#         if in_cat:
#             depth += line.count('{') - line.count('}')
#             m = entry_re.match(line)
#             if m:
#                 return i, m.group(1), m.group(2), m.group(3)
#             if depth == 0:
#                 in_cat = False
#     return None, None, None, None

# def insert_before_close(lines, category, new_line):
#     cat_re = re.compile(rf"^\s*'{category}'\s*:\s*\{{")
#     depth, in_cat = 0, False
#     for i, line in enumerate(lines):
#         if cat_re.match(line):
#             in_cat, depth = True, line.count('{') - line.count('}')
#             continue
#         if in_cat:
#             depth += line.count('{') - line.count('}')
#             if depth == 0:
#                 lines.insert(i, new_line)
#                 return
#     raise ValueError(f"Category {category} not found")

# def main(src, dst):
#     with open(src, encoding='utf-8') as f:
#         lines = f.readlines()

#     log = []

#     for vendor, src_cat, dst_cat in MOVES:
#         key = slug(vendor)
#         idx, indent, full_key, regex_body = find_entry(lines, src_cat, key)
#         if idx is None:
#             log.append(f"NOT FOUND: {vendor} in {src_cat}"); continue
#         del lines[idx]
#         if dst_cat is None:
#             log.append(f"DELETED (duplicate): {vendor} from {src_cat}")
#         else:
#             insert_before_close(lines, dst_cat, f"{indent}'{full_key}': r'{regex_body}',\n")
#             log.append(f"MOVED: {vendor} ({src_cat} -> {dst_cat})")

#     for vendor, src_cat, tokens, dst_cat, suffix in SPLITS:
#         key = slug(vendor)
#         idx, indent, full_key, regex_body = find_entry(lines, src_cat, key)
#         if idx is None:
#             log.append(f"NOT FOUND: {vendor} in {src_cat}"); continue
#         parts = regex_body.strip('()').split('|')
#         remaining = [p for p in parts if p not in tokens]
#         extracted = [p for p in parts if p in tokens]
#         if not extracted:
#             log.append(f"TOKENS NOT MATCHED: {tokens} in {vendor}"); continue
#         lines[idx] = f"{indent}'{full_key}': r'({'|'.join(remaining)})',\n"
#         if dst_cat is not None:
#             new_key = f"{key}_{suffix}"
#             insert_before_close(lines, dst_cat, f"{indent}'{new_key}': r'({'|'.join(extracted)})',\n")
#             log.append(f"SPLIT: {vendor} tokens {extracted} -> {dst_cat} as '{new_key}'")
#         else:
#             log.append(f"REMOVED (duplicate): {vendor} tokens {extracted}")

#     with open(dst, 'w', encoding='utf-8') as f:
#         f.writelines(lines)

#     import ast
#     ast.parse(''.join(lines))  # validate syntax
#     print(f"✓ Written {dst}, syntax valid. {len(log)} operations:")
#     for l in log:
#         print(" ", l)

# if __name__ == "__main__":
#     main(sys.argv[1], sys.argv[2])


#!/usr/bin/env python3




## cleaning version 2


# """
# Robust patch v2: boundaries detected via "next category opening", never
# via closing-brace matching (fragile against \{n\} quantifiers in regex
# values). Also creates the missing TECHNICAL_PASSWORDS category, and
# redirects geo_coordinates to the existing SENSITIVE_LOCATION_PII
# (matches its Table 11 definition: "high-precision coordinates lat/long")
# instead of the non-existent LOCATION_AND_DEMOGRAPHICS.
# """
# import re, sys, ast

# CAT_RE = re.compile(r"^(\s*)'([A-Z_]+)'\s*:\s*\{")

# def category_bounds(lines, category):
#     """Return (start, end) line indices: start = opening line index,
#     end = index of the NEXT category's opening line (or len(lines))."""
#     start = None
#     for i, line in enumerate(lines):
#         m = CAT_RE.match(line)
#         if m and start is None and m.group(2) == category:
#             start = i
#             continue
#         if start is not None and m and m.group(2) != category:
#             return start, i
#     if start is not None:
#         return start, len(lines)
#     return None, None

# def find_entry(lines, category, key_exact):
#     start, end = category_bounds(lines, category)
#     if start is None:
#         return None, None, None
#     entry_re = re.compile(r"^(\s*)'(" + re.escape(key_exact) + r")'\s*:\s*r'((?:[^'\\]|\\.)*)'")
#     for i in range(start, end):
#         m = entry_re.match(lines[i])
#         if m:
#             return i, m.group(1), m.group(3)
#     return None, None, None

# def insert_after_open(lines, category, new_line):
#     start, end = category_bounds(lines, category)
#     if start is None:
#         print(f"  ! category '{category}' not found")
#         return False
#     lines.insert(start + 1, new_line)
#     return True

# def remove_tokens(lines, category, key_exact, tokens_to_remove):
#     idx, indent, body = find_entry(lines, category, key_exact)
#     if idx is None:
#         print(f"  ! '{key_exact}' not found in '{category}'")
#         return None
#     parts = body.strip('()').split('|')
#     extracted = [p for p in parts if p in tokens_to_remove]
#     remaining = [p for p in parts if p not in tokens_to_remove]
#     lines[idx] = f"{indent}'{key_exact}': r'({'|'.join(remaining)})',\n"
#     return extracted

# def relocate_whole(lines, src_cat, key_exact, dst_cat, new_key=None):
#     idx, indent, body = find_entry(lines, src_cat, key_exact)
#     if idx is None:
#         print(f"  ! '{key_exact}' not found in '{src_cat}'")
#         return
#     del lines[idx]
#     if insert_after_open(lines, dst_cat, f"{indent}'{new_key or key_exact}': r'{body}',\n"):
#         print(f"  moved '{key_exact}' -> {dst_cat}")

# def create_category(lines, new_category, after_category):
#     """Insert a fresh, empty category block right after `after_category`'s
#     own block ends (i.e., right before whatever comes next in the file)."""
#     start, end = category_bounds(lines, after_category)
#     if start is None:
#         print(f"  ! anchor category '{after_category}' not found; appending near end")
#         end = len(lines) - 1  # fallback, just before final closing brace
#     indent = re.match(r"^(\s*)", lines[start]).group(1)
#     block = [f"{indent}'{new_category}': {{\n", f"{indent}}},\n"]
#     lines[end:end] = block
#     print(f"  created empty category '{new_category}' after '{after_category}'")

# def main(src, dst):
#     with open(src, encoding='utf-8') as f:
#         lines = f.readlines()

#     print("0) Create missing TECHNICAL_PASSWORDS category")
#     create_category(lines, "TECHNICAL_PASSWORDS", after_category="SUSPICIOUS_VALUES")

#     print("1) Oracle split")
#     extracted = remove_tokens(lines, "SESSION_MANAGEMENT", "vendor_oracle_expansion", ["ELOQUA", "ELQSTATUS"])
#     if extracted:
#         insert_after_open(lines, "ID_SOLUTIONS_AND_EXCHANGES",
#                            f"        'vendor_oracle_eloqua': r'({'|'.join(extracted)})',\n")

#     print("2) Yandex split")
#     consent_tokens = set()
#     for cat, key in [("IDENTITY_TRACKING", "vendor_yandex_expansion"),
#                       ("UX_AND_PERFORMANCE_ANALYTICS", "vendor_yandex_metrica_p2_expansion")]:
#         ext = remove_tokens(lines, cat, key, ["is_gdpr_b", "is_gdpr"])
#         if ext:
#             consent_tokens.update(ext)
#     if consent_tokens:
#         insert_after_open(lines, "CONSENT_AND_PRIVACY",
#                            f"    'yandex_consent': r'({'|'.join(sorted(consent_tokens))})',\n")

#     print("3) SUSPICIOUS_VALUES relocation")
#     RELOCATIONS = [
#         ("jwt_token", "TECHNICAL_PASSWORDS"),
#         ("auth_tokens", "TECHNICAL_PASSWORDS"),
#         ("auth0_patterns", "TECHNICAL_PASSWORDS"),
#         ("api_keys", "TECHNICAL_PASSWORDS"),
#         ("uuid_format", "IDENTITY_TRACKING"),
#         ("geo_coordinates", "SENSITIVE_LOCATION_PII"),   # corrected target
#         ("url_list", "BEHAVIORAL_DATA"),
#         ("google_rollout", "UX_AND_PERFORMANCE_ANALYTICS"),
#         ("base64_json", "APP_STATE_STORAGE"),
#         ("php_serialized", "APP_STATE_STORAGE"),
#     ]
#     for key, dst_cat in RELOCATIONS:
#         relocate_whole(lines, "SUSPICIOUS_VALUES", key, dst_cat)

#     content = ''.join(lines)
#     ast.parse(content)
#     with open(dst, 'w', encoding='utf-8') as f:
#         f.write(content)
#     print(f"\n✓ Written {dst}, syntax valid.")

# if __name__ == "__main__":
#     main(sys.argv[1], sys.argv[2])


#!/usr/bin/env python3
"""
Relocate ~57 entries out of ID_SOLUTIONS_AND_EXCHANGES that don't meet the
cross-party identity-brokering criterion, into their correct category.

Usage: python3 relocate_id_solutions.py regex_v2.py regex_v3.py
"""
import re, sys, ast

CAT_RE = re.compile(r"^\s*'([A-Z_]+)'\s*:\s*\{")

def category_bounds(lines, category):
    """(start, end): start=opening line idx, end=next category's opening idx."""
    start = None
    for i, line in enumerate(lines):
        m = CAT_RE.match(line)
        if m and start is None and m.group(1) == category:
            start = i
            continue
        if start is not None and m and m.group(1) != category:
            return start, i
    return (start, len(lines)) if start is not None else (None, None)

def find_entry(lines, category, key_exact):
    start, end = category_bounds(lines, category)
    if start is None:
        return None, None, None
    entry_re = re.compile(r"^(\s*)'(" + re.escape(key_exact) + r")'\s*:\s*r'((?:[^'\\]|\\.)*)'")
    for i in range(start, end):
        m = entry_re.match(lines[i])
        if m:
            return i, m.group(1), m.group(3)
    return None, None, None

def insert_after_open(lines, category, new_line):
    start, end = category_bounds(lines, category)
    if start is None:
        print(f"  ! category '{category}' not found")
        return False
    lines.insert(start + 1, new_line)
    return True

def relocate(lines, key, src_cat, dst_cat):
    idx, indent, body = find_entry(lines, src_cat, key)
    if idx is None:
        print(f"  ! '{key}' not found in '{src_cat}'")
        return
    del lines[idx]
    if insert_after_open(lines, dst_cat, f"{indent}'{key}': r'{body}',\n"):
        print(f"  moved '{key}' -> {dst_cat}")

# --- (vendor_key, target_category) ---
MOVES = [
    # Family 1: single-platform, own-ecosystem recognition -> IDENTITY_TRACKING
    ("linkedin_extended", "IDENTITY_TRACKING"),
    ("vendor_linkedin_p2_expansion", "IDENTITY_TRACKING"),
    ("twitter_extended", "IDENTITY_TRACKING"),
    ("vendor_x_p2_expansion", "IDENTITY_TRACKING"),
    ("amazon_extended", "IDENTITY_TRACKING"),
    ("vendor_google_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_facebook_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_pinterest_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_instagram_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_reddit_expansion", "IDENTITY_TRACKING"),
    ("vendor_roku_expansion", "IDENTITY_TRACKING"),
    ("vendor_snap_expansion", "IDENTITY_TRACKING"),
    ("vendor_snapchat_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_spotify_expansion", "IDENTITY_TRACKING"),
    ("bing_mr", "IDENTITY_TRACKING"),
    ("vendor_bing_microsoft_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_tiktok_p2_expansion", "IDENTITY_TRACKING"),
    ("dailymotion", "IDENTITY_TRACKING"),

    # Family 2: single-company MarTech/CDP/CRM -> IDENTITY_TRACKING
    ("vendor_braze_expansion", "IDENTITY_TRACKING"),
    ("vendor_hubspot_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_customer_io_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_rd_station_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_sap_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_sharpspring_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_active_campaign_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_exponea_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_datatrics_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_squeezely_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_mailmunch_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_sailthru_p2_expansion", "IDENTITY_TRACKING"),
    ("vendor_command_act_p2_expansion", "IDENTITY_TRACKING"),
    ("mediarithmics", "IDENTITY_TRACKING"),
    ("vendor_rudderstack_expansion", "IDENTITY_TRACKING"),

    # Family 3: pure measurement/analytics, no cross-party brokering -> UX_AND_PERFORMANCE_ANALYTICS
    ("vendor_nielsen_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_dotmetrics_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_gemius_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_adalyser_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_adalyser_com_p2_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_marfeel_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_comscore_p2_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_optimizely_p2_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_emetric_p2_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),
    ("vendor_quantcast_p2_expansion", "UX_AND_PERFORMANCE_ANALYTICS"),

    # Family 4: single-site widgets / unrelated vendors -> mixed targets
    ("vendor_disqus_expansion", "IDENTITY_TRACKING"),
    ("vendor_viafoura_expansion", "BEHAVIORAL_DATA"),
    ("vendor_trustpilot_expansion", "IDENTITY_TRACKING"),
    ("vendor_beamer_p2_expansion", "APP_STATE_STORAGE"),
    ("vendor_snapengage_p2_expansion", "APP_STATE_STORAGE"),
    ("vendor_qualaroo_p2_expansion", "APP_STATE_STORAGE"),
    ("vendor_bouncex_p2_expansion", "BEHAVIORAL_DATA"),
    ("vendor_monster_expansion", "APP_STATE_STORAGE"),
    ("vendor_adcalls_p2_expansion", "BEHAVIORAL_DATA"),
    ("vendor_leadinfo_expansion", "IDENTITY_TRACKING"),
    ("vendor_funda_p2_expansion", "APP_STATE_STORAGE"),
    ("vendor_google_maps_p2_expansion", "DEVICE_ENV"),
    ("vendor_ortec_p2_expansion", "APP_STATE_STORAGE"),
    ("vendor_totvs_expansion", "APP_STATE_STORAGE"),
]

def main(src, dst):
    with open(src, encoding='utf-8') as f:
        lines = f.readlines()

    print(f"Relocating {len(MOVES)} entries out of ID_SOLUTIONS_AND_EXCHANGES...\n")
    for key, dst_cat in MOVES:
        relocate(lines, key, "ID_SOLUTIONS_AND_EXCHANGES", dst_cat)

    content = ''.join(lines)
    ast.parse(content)
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"\n✓ Written {dst}, syntax valid.")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])