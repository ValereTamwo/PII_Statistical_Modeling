#!/usr/bin/env python3
"""
POST-AI REGEX CORRECTION PATTERNS - indexeddb, country extension.

Context: after ai_parallel_indexededdb.py + ai_indexeddb_correction.py, ~52%
of all indexeddb fields remain in UNCATEGORIZED.json. Auditing the biggest
contributing sites showed this is NOT uniformly "bulk technical noise":
most of it genuinely has no evidence of PII/tracking (gamesnacks.com's
cached JS/CSS modules, bwin.pt's product search index, burgerme.de's raw
SQLite blob, decarocalzature.com's i18n strings, pwcportugal.csod.com's app
config, cocooncenter.de/shop.fck.de's static WonderPush push-SDK config),
but a meaningful slice is real tracking/behavioral data that slipped past
both the regex first pass and the AI passes because it comes from
third-party SDKs with field-naming schemes (analytics event queues,
session-replay recorders, ad-targeting context tags) that the existing
TRACKING_PATTERNS_COMPLETE (regex_merged_v3.py) has no patterns for.

This file is deliberately kept SEPARATE from regex_merged_v3.py:
  - it targets a narrow, audited set of SDK signatures, not general PII/
    tracking vocabulary, and is meant to run only as a correction pass over
    fields already reviewed and left UNCATEGORIZED by the AI passes;
  - each rule matches on the FULL field_path (not just the leaf key, unlike
    categorize_idb_field's engine) so that generic-looking leaf names (e.g.
    "si", "url", "value") only match when they occur under the distinctive
    structural prefix of the SDK they were identified in - this trades a bit
    of recall (fully generic sibling fields with no distinctive marker, e.g.
    a bare "method" or "status" inside a YouTube log_event record, are left
    UNCATEGORIZED) for much higher precision (no risk of sweeping up an
    unrelated field elsewhere in the dataset that happens to share a leaf
    name).

Each rule is independently reviewable: category/subcategory (existing
taxonomy from TRACKING_PATTERNS_COMPLETE), the site it was found on, the
evidence that justified it, and the regex itself.
"""

import re

# =====================================================================
# RULES
# =====================================================================
# path_pattern : matched with re.search(pattern, field_path, re.IGNORECASE)
# value_pattern : optional; if present, ALSO matched against str(value)
#                 (re.search, re.IGNORECASE) for the rule to apply.

POST_AI_CORRECTION_RULES = [

    # ---- youtube.com: queued analytics requests to /youtubei/v1/log_event
    # (options.headers.*, postParams, appInstallData) - this is a batched
    # telemetry/analytics queue, not application plumbing.
    {
        "rule_id": "youtube_log_event_headers",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "youtube_log_event_queue",
        "path_pattern": r"(X-Goog-Request-Time|X-Goog-Event-Time|X-Goog-AuthUser|X-Origin|postBodyFormat|appInstallData|sendCount)$",
        "value_pattern": None,
        "site_evidence": "youtube.com",
        "sample": "[5].options.headers.X-Goog-Request-Time = 1787218539049",
    },
    {
        "rule_id": "youtube_log_event_url",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "youtube_log_event_queue",
        "path_pattern": r"\.url$",
        "value_pattern": r"/youtubei/v1/log_event",
        "site_evidence": "youtube.com",
        "sample": "[5].url = /youtubei/v1/log_event?alt=json",
    },

    # ---- noticiasaominuto.com: OneSignal push-notification persistent
    # tracking identifier.
    {
        "rule_id": "onesignal_push_id",
        "category": "IDENTITY_TRACKING",
        "subcategory": "onesignal_push_id",
        "path_pattern": r"onesignal_id$|onesignal_user_id$|onesignal_player_id$",
        "value_pattern": None,
        "site_evidence": "noticiasaominuto.com",
        "sample": "[20].onesignal_id = local-1c363249-a441-448a-a840-987f2f0d575f",
    },

    # ---- metaloop.com: session-replay recorder (FullStory-style) -
    # replayId/replayStartUrl/batchStartUrl are the recorder's own session
    # markers (batchStartUrl carries a persistent distinctId query param).
    {
        "rule_id": "session_replay_recorder",
        "category": "IDENTITY_TRACKING",
        "subcategory": "session_replay_tracking",
        "path_pattern": r"\.(replayId|replayStartTime|replayStartUrl|batchStartUrl)$",
        "value_pattern": None,
        "site_evidence": "metaloop.com",
        "sample": "[4].batchStartUrl = https://www.metaloop.com/pro/?lng=de&distinctId=f69d46fe-...",
    },

    # ---- m.apkpure.com: client-side analytics event queue
    # (eventCode/eventTime alongside an eventId per queued event).
    {
        "rule_id": "client_analytics_event_queue",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "client_event_queue",
        "path_pattern": r"\.(eventCode|eventTime)$",
        "value_pattern": None,
        "site_evidence": "m.apkpure.com",
        "sample": "[2].value.eventCode = rqd_js_init",
    },

    # ---- services.sdiapi.com: analytics beacon with a session id (si) and
    # page-view id (both the same UUID in the samples seen) sent alongside
    # site/page info to a dedicated "reportServer".
    {
        "rule_id": "sdiapi_analytics_session_id",
        "category": "IDENTITY_TRACKING",
        "subcategory": "analytics_session_id",
        "path_pattern": r"eventData\.(si|pageView)$",
        "value_pattern": None,
        "site_evidence": "services.sdiapi.com",
        "sample": "[5].eventData.si = 608e399f-c214-4245-ad02-94bf13989f2c",
    },
    {
        "rule_id": "sdiapi_analytics_event_meta",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "analytics_event_session",
        "path_pattern": r"eventData\.(siteId|url|buildTimestamp|trafficPercentage|isFirstParty|policy|noSi)$|\.reportServer$",
        "value_pattern": None,
        "site_evidence": "services.sdiapi.com",
        "sample": "[5].eventData.url = https://www.skechers.de/",
    },

    # ---- tibia.fandom.com: ad-exchange contextual/demographic targeting
    # tags (esrb rating, sex-based ad targeting, content bundles).
    {
        "rule_id": "ad_demographic_targeting_tags",
        "category": "LOCATION_AND_DEMOGRAPHICS",
        "subcategory": "ad_demographic_targeting_tags",
        "path_pattern": r"adTags\.(sex|esrb|bundles)",
        "value_pattern": None,
        "site_evidence": "tibia.fandom.com",
        "sample": "[6].context.adTags.sex.values[0] = f",
    },

    # ---- freshchat.com: chat-widget visitor tracking - a persistent
    # visitor alias plus the page-visit / event log recorded under it.
    {
        "rule_id": "freshchat_visitor_alias",
        "category": "IDENTITY_TRACKING",
        "subcategory": "freshchat_visitor_alias",
        "path_pattern": r"datastore\.records\.[^.]+\.alias$",
        "value_pattern": None,
        "site_evidence": "freshchat.com",
        "sample": "[5].datastore.records.e88421af-....alias = 0a804f05-0f2d-4703-9b50-1446d21256ac",
    },
    {
        "rule_id": "freshchat_page_visit",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "freshchat_page_visit",
        "path_pattern": r"userBehaviour\.locations\..*\.pageUrl$",
        "value_pattern": None,
        "site_evidence": "freshchat.com",
        "sample": "[5].datastore.records...userBehaviour.locations.properties.0.pageUrl = https://www.basko.it/",
    },
    {
        "rule_id": "freshchat_event_tracking",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "freshchat_page_visit",
        "path_pattern": r"userBehaviour\.events\..*\.value$",
        "value_pattern": None,
        "site_evidence": "freshchat.com",
        "sample": "[5]...userBehaviour.events.properties.0.eventProperties.properties.1.value = Basko Home Page - Basko",
    },

    # ---- primevideo.com: internal app action/page-view log (redux-style
    # action dispatch log tagged with page type and activity timestamps).
    {
        "rule_id": "app_page_action_tracking",
        "category": "BEHAVIORAL_DATA",
        "subcategory": "app_page_action_tracking",
        "path_pattern": r"\.(pageType|subPageType|attribution|actionType|lastUserActiveTime)$",
        "value_pattern": None,
        "site_evidence": "primevideo.com",
        "sample": "[2].count.values[0].args.values[3].pageType = ATVDetail",
    },
]


def get_rules():
    return POST_AI_CORRECTION_RULES


def match_item(field_path: str, value) -> dict | None:
    """Returns the first matching rule's {category, subcategory, rule_id}, or None."""
    val_str = str(value) if value is not None else ""
    for rule in POST_AI_CORRECTION_RULES:
        if re.search(rule["path_pattern"], field_path, re.IGNORECASE):
            vp = rule.get("value_pattern")
            if vp and not re.search(vp, val_str, re.IGNORECASE):
                continue
            return {
                "rule_id": rule["rule_id"],
                "category": rule["category"],
                "subcategory": rule["subcategory"],
            }
    return None
