import re

with open('regex_merged_v2.py', encoding='utf-8') as f:
    content = f.read()

ENTRY_RE = re.compile(r"(r'\(([^)]*)\)')")

def anchor_short_tokens(match):
    full, body = match.groups()
    branches = body.split('|')
    fixed = []
    for b in branches:
        core_alpha = re.sub(r'\\.', '', b)
        has_anchor = bool(re.search(r'\^|\$|\\b|\(\?', b))
        if not has_anchor and 1 <= len(core_alpha) <= 4 and core_alpha.isalnum():
            fixed.append(f'^{b}$')
        else:
            fixed.append(b)
    return f"r'({'|'.join(fixed)})'"

new_content = ENTRY_RE.sub(anchor_short_tokens, content)
with open('regex_merged_v3.py', 'w', encoding='utf-8') as f:
    f.write(new_content)