import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from countries_config import USERS

NAV_MODES = ['AUTH', 'NOTAUTH']
POLICIES = ['PARTIAL']

# Number of profiles per nav_mode = len(USERS) * len(POLICIES); per user = len(NAV_MODES) * len(POLICIES).
PROFILES_PER_NAV_MODE = len(USERS) * len(POLICIES)
CONFIGS_PER_USER = len(NAV_MODES) * len(POLICIES)


def load_comparative_analysis(reports_dir):
    """Load comparative analysis results from JSON."""
    path = os.path.join(reports_dir, 'pii_comparative_analysis.json')
    with open(path, 'r') as f:
        return json.load(f)


def load_all_profiles(outputs_dir):
    """Descriptive metadata for all profile configurations."""
    profiles = []

    for nav_mode in NAV_MODES:
        nav_path = os.path.join(outputs_dir, nav_mode)
        if not os.path.exists(nav_path):
            continue

        for user_id in os.listdir(nav_path):
            user_path = os.path.join(nav_path, user_id)
            if not os.path.isdir(user_path):
                continue

            for policy in os.listdir(user_path):
                policy_path = os.path.join(user_path, policy)
                if not os.path.isdir(policy_path):
                    continue

                profile = {
                    'nav_mode': nav_mode,
                    'user_id': user_id,
                    'policy': policy,
                    'profile_id': f"{nav_mode}_{user_id}_{policy}"
                }

                for json_file in ['pii_aggregation_summary.json']:
                    json_path = os.path.join(policy_path, json_file)
                    if os.path.exists(json_path):
                        with open(json_path, 'r') as f:
                            profile[json_file.replace('.json', '')] = json.load(f)

                profiles.append(profile)

    return profiles


def compute_global_statistics(comparative_data):
    """Calculate high-level metrics across entire dataset."""
    stats = {}

    overall = comparative_data.get('overall_statistics', {})
    stats['total_profiles'] = overall.get('total_profiles', 0)
    stats['total_pii_instances'] = overall.get('total_pii_instances', 0)
    stats['avg_pii_per_profile'] = stats['total_pii_instances'] / stats['total_profiles'] if stats['total_profiles'] > 0 else 0

    stats['total_uncategorized_items'] = overall.get('total_uncategorized_items', 0)
    stats['total_pii_instances_with_uncategorized'] = overall.get('total_pii_instances_with_uncategorized', stats['total_pii_instances'])

    by_category = overall.get('by_category', {})
    stats['category_distribution'] = sorted(by_category.items(), key=lambda x: x[1], reverse=True)

    stats['cookie_security'] = overall.get('cookie_security', {})

    return stats


def compute_auth_statistics(comparative_data):
    """Compute statistics by authentication status (AUTH vs NOTAUTH)."""
    by_nav = comparative_data.get('by_nav_mode', {})

    auth_stats = {}
    for nav_mode in NAV_MODES:
        if nav_mode in by_nav:
            data = by_nav[nav_mode]
            auth_stats[nav_mode] = {
                'total_items': data.get('total_items', 0),
                'total_items_with_uncategorized': data.get('total_items_with_uncategorized', data.get('total_items', 0)),
                'by_user': data.get('by_user', {}),
                'by_policy': data.get('by_policy', {})
            }

    if 'AUTH' in auth_stats and 'NOTAUTH' in auth_stats:
        auth_total = auth_stats['AUTH']['total_items']
        notauth_total = auth_stats['NOTAUTH']['total_items']
        auth_stats['ratio_notauth_vs_auth'] = notauth_total / auth_total if auth_total > 0 else 0

        auth_total_uncat = auth_stats['AUTH']['total_items_with_uncategorized']
        notauth_total_uncat = auth_stats['NOTAUTH']['total_items_with_uncategorized']
        auth_stats['ratio_notauth_vs_auth_with_uncategorized'] = (
            notauth_total_uncat / auth_total_uncat if auth_total_uncat > 0 else 0
        )

    return auth_stats


def compute_user_statistics(comparative_data):
    """Compute statistics by country user."""
    by_user = comparative_data.get('by_user', {})

    user_stats = {}
    for user_id in USERS:
        if user_id in by_user:
            data = by_user[user_id]
            user_stats[user_id] = {
                'total_items': data.get('total_items', 0),
                # CONFIGS_PER_USER = nav_modes x policies per user (2 x 1 = 2 for country data)
                'avg_per_config': data.get('total_items', 0) / CONFIGS_PER_USER if CONFIGS_PER_USER else 0,
                'by_policy': data.get('by_policy', {}),
                'by_nav_mode': data.get('by_nav_mode', {}),
                'cookie_security': data.get('cookie_security', {})
            }

    return user_stats


def write_cookie_security_block(f, cookie_sec):
    """
    Writes the detailed per-attribute security breakdown (httpOnly, secure,
    sameSite, third-party) plus the derived posture, for one cookie_security
    block (global or per-country).
    """
    total = cookie_sec.get('total_cookies', 0)
    f.write(f"  Total Cookies: {total:,}\n")
    if not total:
        return

    def pct_line(label, count):
        pct = count / total * 100
        f.write(f"    {label:22s} {count:8,} ({pct:5.1f}%)\n")

    httponly = cookie_sec.get('httponly_distribution', {})
    f.write("  httpOnly:\n")
    pct_line('True', httponly.get('True', 0))
    pct_line('False', httponly.get('False', 0))

    secure = cookie_sec.get('secure_distribution', {})
    f.write("  secure:\n")
    pct_line('True', secure.get('True', 0))
    pct_line('False', secure.get('False', 0))

    samesite = cookie_sec.get('samesite_distribution', {})
    f.write("  sameSite:\n")
    for k, count in sorted(samesite.items(), key=lambda x: -x[1]):
        pct_line(k, count)

    thirdparty = cookie_sec.get('thirdparty_distribution', {})
    f.write("  Third-party vs First-party:\n")
    pct_line('Third-Party', thirdparty.get('Third-Party', 0))
    pct_line('First-Party', thirdparty.get('First-Party', 0))

    posture = cookie_sec.get('security_posture_distribution', {})
    f.write("  Security Posture (derived from httpOnly + secure):\n")
    for p in ['Secure', 'Partially Secure', 'Lowly Secure']:
        pct_line(p, posture.get(p, 0))


def generate_report(output_file, comparative_data):
    """Generate comprehensive reproducibility report for the country dataset."""

    with open(output_file, 'w', encoding='utf-8') as f:

        # Section 1: Global Statistics
        f.write("SECTION 1: GLOBAL STATISTICS\n")
        f.write("-" * 80 + "\n")
        global_stats = compute_global_statistics(comparative_data)

        f.write(f"Total PII Instances (categorized only): {global_stats['total_pii_instances']:,}\n")
        f.write(f"Total UNCATEGORIZED Items (excluded above, moved to user_countries_raws/): {global_stats['total_uncategorized_items']:,}\n")
        f.write(f"Total Items Including UNCATEGORIZED: {global_stats['total_pii_instances_with_uncategorized']:,}\n")
        f.write(f"Total Profiles: {global_stats['total_profiles']}\n")
        f.write(f"Average PII per Profile: {global_stats['avg_pii_per_profile']:,.1f}\n\n")

        total = global_stats['total_pii_instances']

        f.write("Top 10 PII Categories by Volume:\n")
        for i, (category, count) in enumerate(global_stats['category_distribution'][:10], 1):
            percentage = (count / total * 100) if total > 0 else 0
            f.write(f"  {i:2d}. {category:40s} {count:8,} ({percentage:5.1f}%)\n")
        f.write("\n")

        f.write("Cookie Security (all countries, all cookies):\n")
        write_cookie_security_block(f, global_stats['cookie_security'])
        f.write("\n")

        # Section 2: Authentication Impact
        f.write("SECTION 2: AUTHENTICATION STATUS IMPACT (AUTH vs NOTAUTH)\n")
        f.write("-" * 80 + "\n")
        auth_stats = compute_auth_statistics(comparative_data)

        auth_total = auth_stats.get('AUTH', {}).get('total_items', 0)
        notauth_total = auth_stats.get('NOTAUTH', {}).get('total_items', 0)
        ratio = auth_stats.get('ratio_notauth_vs_auth', 0)

        auth_total_uncat = auth_stats.get('AUTH', {}).get('total_items_with_uncategorized', auth_total)
        notauth_total_uncat = auth_stats.get('NOTAUTH', {}).get('total_items_with_uncategorized', notauth_total)
        ratio_uncat = auth_stats.get('ratio_notauth_vs_auth_with_uncategorized', 0)

        f.write(f"AUTH (authenticated users) - categorized items only:\n")
        f.write(f"  Total Items: {auth_total:,}\n")
        f.write(f"  Average per Profile ({PROFILES_PER_NAV_MODE} profiles): {auth_total/PROFILES_PER_NAV_MODE:,.1f}\n\n")

        f.write(f"NOTAUTH (non-authenticated users) - categorized items only:\n")
        f.write(f"  Total Items: {notauth_total:,}\n")
        f.write(f"  Average per Profile ({PROFILES_PER_NAV_MODE} profiles): {notauth_total/PROFILES_PER_NAV_MODE:,.1f}\n\n")

        f.write(f"Ratio NOTAUTH/AUTH (categorized only): {ratio:.2f}\n\n")

        f.write(f"Including UNCATEGORIZED items (moved to user_countries_raws/ by clean_user_folder.py,\n")
        f.write(f"not seen by the categorized-only totals above):\n")
        f.write(f"  AUTH total (incl. UNCATEGORIZED): {auth_total_uncat:,}\n")
        f.write(f"  NOTAUTH total (incl. UNCATEGORIZED): {notauth_total_uncat:,}\n")
        f.write(f"  Ratio NOTAUTH/AUTH (incl. UNCATEGORIZED): {ratio_uncat:.2f}\n\n")

        # Section 3 (Consent Policy Impact) omitted: country data was collected under a
        # single PARTIAL policy only (no ALL/NONE variation to compare against),
        # unlike the FR dataset.

        # Section 4: Inter-user (inter-country) variability
        f.write("SECTION 3: INTER-COUNTRY VARIABILITY\n")
        f.write("-" * 80 + "\n")
        user_stats = compute_user_statistics(comparative_data)

        for user_id in USERS:
            if user_id in user_stats:
                stats = user_stats[user_id]
                f.write(f"{user_id}:\n")
                f.write(f"  Total Items: {stats['total_items']:,}\n")
                f.write(f"  Average per Config ({CONFIGS_PER_USER} configs): {stats['avg_per_config']:,.1f}\n\n")

        totals = [user_stats[u]['total_items'] for u in USERS if u in user_stats]
        if totals:
            max_total = max(totals)
            min_total = min(totals)
            max_user = [u for u in USERS if u in user_stats and user_stats[u]['total_items'] == max_total][0]
            min_user = [u for u in USERS if u in user_stats and user_stats[u]['total_items'] == min_total][0]
            f.write(f"Highest volume: {max_user} ({max_total:,})\n")
            f.write(f"Lowest volume: {min_user} ({min_total:,})\n")
            f.write(f"Variability Ratio (Max/Min): {max_total/min_total:.2f}\n\n" if min_total else "Variability Ratio (Max/Min): n/a (min=0)\n\n")

        # Section 4: Cookie security detail per country
        f.write("SECTION 4: COOKIE SECURITY NON-CONFORMITY BY COUNTRY\n")
        f.write("-" * 80 + "\n")
        for user_id in USERS:
            if user_id not in user_stats:
                continue
            cookie_sec = user_stats[user_id].get('cookie_security', {})

            f.write(f"{user_id}:\n")
            write_cookie_security_block(f, cookie_sec)
            f.write("\n")


def main():
    """Main execution."""
    base_dir = Path(__file__).parent.parent
    reports_dir = base_dir / 'reports'
    outputs_dir = base_dir / 'outputs'

    print("Loading data...")
    comparative_data = load_comparative_analysis(reports_dir)
    profiles = load_all_profiles(outputs_dir)

    print(f"Loaded {len(profiles)} profiles")

    output_file = reports_dir / 'reproducibility_report.txt'
    print(f"Generating report: {output_file}")

    generate_report(output_file, comparative_data)
    print(f" Report generated successfully!")
    print(f"  Location: {output_file}")
    print(f"  Profiles analyzed: {len(profiles)}")
    print(f"  Total PII instances: {comparative_data['overall_statistics']['total_pii_instances']:,}")


if __name__ == '__main__':
    main()
