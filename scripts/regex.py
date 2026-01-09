TRACKING_PATTERNS_COMPLETE = {
    
    # DIRECT_PII est maintenant une LISTE de patterns, un par utilisateur
    # Index 0 = FR_0417, Index 1 = FR_0418, Index 2 = FR_0419
'DIRECT_PII': [
    # ===== USER FR_0417 =====
    {
        # Email patterns - exact and partial
        'email_exact': r'chris\.martin\.gdpr\+FR_0417@gmail\.com',
        'email_encoded': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr(?:%2B|\+)FR_0417(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr',
        'email_pattern': r'chris(?:%2E|\.)martin|FR_0417',
        
        # Phone patterns - various formats and encoded
        'phone_full': r'\+33\s?656898637',
        'phone_national': r'0656898637',
        'phone_short': r'656898637',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?656898637',
        'phone_partial': r'6568986[0-9]{2}|65689863[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?56\s?89\s?86\s?37',
        
        # Name patterns - full and partial
        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',
        
        # Address patterns - full and components
        'address_full': r'688,?\s*avenue\s+Thérèse\s+Robin',
        # 'address_number': r'\b688\b',
        'address_street': r'avenue\s+Thérèse\s+Robin',
        'address_encoded': r'688(?:%2C|,)?\s*avenue(?:%20|\s)Thérèse(?:%20|\s)Robin',
        
        # City
        'city': r'\bRoubaix\b',
        'city_encoded': r'Roubaix',
        
        # Birth date - multiple formats (full date only to avoid false positives)
        'birth_date_slash': r'26/11/2005',
        'birth_date_iso': r'2005-11-26',
        'birth_date_dot': r'26\.11\.2005',
        'birth_date_full': r'26[/\-\.]11[/\-\.]2005',
        
        # User ID
        'user_id': r'\bFR_0417\b',
        'user_id_partial': r'FR_04[0-9]{2}|FR_041[0-9]',
        
        # Password (for leak detection)
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',
        
        # Blood type
        # 'blood_type': r'\bAB-\b',
        
        # Gender
        'gender': r'\bFemme\b|\bFemale\b',
        
        # Location patterns
        'postal_code_area': r'\b59\d{3}\b',  # Roubaix area
        'region': r'\bHauts-de-France\b',
        
        # Socio-economic markers
        'income_range': r'0-12000',
        'housing': r'\bHLM\b',
        'employment': r'non\s+déclarés?',
        
        # Demographics
        'religion': r'\bMusulman\b',
        'marital_status': r'\bCélibataire\b',
        
        # Combined patterns (often appear together)
        'name_and_city': r'Chris\s+Martin.*Roubaix|Roubaix.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*656898637|656898637.*chris\.martin',
    },
    
    # ===== USER FR_0446 =====
    {
        # Email patterns - exact and partial
        'email_exact': r'chris\.martin\.gdpr\+FR_0446@gmail\.com',
        'email_encoded': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr(?:%2B|\+)FR_0446(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr',
        'email_pattern': r'chris(?:%2E|\.)martin|FR_0446',
        
        # Phone patterns - various formats and encoded
        'phone_full': r'\+33\s?606124448',
        'phone_national': r'0606124448',
        'phone_short': r'606124448',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?606124448',
        'phone_partial': r'6061244[0-9]{2}|60612444[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?06\s?12\s?44\s?48',
        
        # Name patterns - full and partial
        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',
        
        # Address patterns - full and components
        'address_full': r'75,?\s*chemin\s+Margaux\s+Lombard',
        # 'address_number': r'\b75\b',
        'address_street': r'chemin\s+Margaux\s+Lombard',
        'address_encoded': r'75(?:%2C|,)?\s*chemin(?:%20|\s)Margaux(?:%20|\s)Lombard',
        
        # City
        'city': r'\bParis\s+16(?:ème|e)\b',
        'city_encoded': r'Paris(?:%20|\s)16(?:ème|e)?',
        'arrondissement': r'\b75016\b',
        
        # Birth date - multiple formats
        'birth_date_slash': r'14/05/1975',
        'birth_date_iso': r'1975-05-14',
        'birth_date_dot': r'14\.05\.1975',
        'birth_date_full': r'14[/\-\.]05[/\-\.]1975',
        
        # User ID
        'user_id': r'\bFR_0446\b',
        'user_id_partial': r'FR_04[0-9]{2}|FR_044[0-9]',
        
        # Password (for leak detection)
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',
        
        # Blood type
        # 'blood_type': r'\bA\+\b',
        
        # Gender
        'gender': r'\bHomme\b|\bMale\b',
        
        # Location patterns
        'postal_code_area': r'\b750\d{2}\b',  # Paris
        'region': r'\bÎle-de-France\b',
        
        # Socio-economic markers
        'income_range': r'70000-120000|70000|120000',
        'profession': r'\bAvocat\b',
        'employment': r'\bLibéral\b',
        
        # Demographics
        'religion': r'\bLaïc\b|\bLaïque\b',
        'marital_status': r'\bMarié\b',
        'children': r'2\s+enfants?',
        
        # Lifestyle
        'loisirs': r'\bGolf\b|\bVoyages?\b',
        
        # Combined patterns
        'name_and_city': r'Chris\s+Martin.*Paris|Paris.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*606124448|606124448.*chris\.martin',
        'profession_and_city': r'Avocat.*Paris\s+16|Paris\s+16.*Avocat',
    },
    
    # ===== USER FR_0458 =====
    {
        # Email patterns - exact and partial
        'email_exact': r'chris\.martin\.gdpr\+FR_0458@gmail\.com',
        'email_encoded': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr(?:%2B|\+)FR_0458(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris(?:%2E|\.)martin(?:%2E|\.)gdpr',
        'email_pattern': r'chris(?:%2E|\.)martin|FR_0458',
        
        # Phone patterns - various formats and encoded
        'phone_full': r'\+33\s?653277579',
        'phone_national': r'0653277579',
        'phone_short': r'653277579',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?653277579',
        'phone_partial': r'6532775[0-9]{2}|65327757[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?53\s?27\s?75\s?79',
        
        # Name patterns - full and partial
        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',
        
        # Address patterns - full and components
        'address_full': r'74,?\s*boulevard\s+Lenoir',
        # 'address_number': r'\b74\b',
        'address_street': r'boulevard\s+Lenoir',
        'address_encoded': r'74(?:%2C|,)?\s*boulevard(?:%20|\s)Lenoir',
        
        # City
        'city': r'\bThibault\b',
        'city_encoded': r'Thibault',
        
        # Birth date - multiple formats
        'birth_date_slash': r'24/01/1966',
        'birth_date_iso': r'1966-01-24',
        'birth_date_dot': r'24\.01\.1966',
        'birth_date_full': r'24[/\-\.]01[/\-\.]1966',
        
        # User ID
        'user_id': r'\bFR_0458\b',
        'user_id_partial': r'FR_04[0-9]{2}|FR_045[0-9]',
        
        # Password (for leak detection)
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',
        
        # Blood type
        # 'blood_type': r'\bA\+\b',
        
        # Gender
        'gender': r'\bFemme\b|\bFemale\b',
        
        # Socio-economic markers
        'income_range': r'15000-30000|15000|30000',
        'employment': r'\bTemps\s+partiel\b',
        'situation': r'\bAidant\b',
        
        # Health-related (sensitive)
        'health_marker': r'\bcancer\b',
        'dependent': r'\bpère\b.*charge|parent.*charge',
        
        # Demographics
        'religion': r'\bCatholique\b',
        'marital_status': r'\bMarié\b',
        'household': r'parent\s+à\s+charge',
        
        # Lifestyle
        'loisirs': r'\bÉglise\b',
        'constraints': r'\bBurnout\b',
        
        # Combined patterns
        'name_and_city': r'Chris\s+Martin.*Thibault|Thibault.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*653277579|653277579.*chris\.martin',
        'aidant_context': r'aidant.*père|père.*cancer',
    }
],

    'ID_SOLUTIONS_AND_EXCHANGES': {
        'first_id': r'(firstid|firstid_consent)',
        'id5_sync': r'(\bid5\b|^3pi$|id5-sync|id5id)',
        'zeotap': r'(\bzc\b|zsc|zeotap)',
        'mediarithmics': r'(mics_lts|mics_uaid|mics_vid|mics_)',
        'pubmatic': r'(KRTBCOOKIE|SPugT|DPSync4|pubsyncexp|pubmatic)',
        'shared_id': r'(_sharedid|_sharedid_cst)',
        'openx': r'(^i$|^pd$|openx)',
        'smart_adserver': r'(csfq|lcsrd|csync|smartadserver)',
        'contextweb': r'(^V$|INGRESSCOOKIE|contextweb)',
        'adotmob': r'(pixel.*adotmob)',
        'liveramp': r'(_lr_.*|liveramp)',
        'widespace': r'(widespace|dsp_)',
        'taboola_outbrain': r'(taboola|outbrain|obuid|t_gid)',
        'criteo_extended': r'(criteo|cto_bundle|cto_bidid|cto_id)',
        'linkedin_extended': r'(li_fat_id|lidc|bcookie|bscookie|linkedin)',
        'twitter_extended': r'(guest_id|personalization_id|^muc$|twid|twitter)',
        'amazon_extended': r'(apbct|amazon-adsystem)',
        'dailymotion': r'(dmvk|dailymotion)',
        'weborama': r'(AFFICHE_W|weborama)',
        'piano_io': r'(_pctx|_pcid|piano)',
        'rossel_advertising': r'(_pprv|rossel)',
        'agkn': r'(^u$|agkn)',
        'blismedia': r'(^b$|blismedia)',
        'creativecdn': r'(^c$|creativecdn)',
        'bing_mr': r'(^MR$)',
        'rtb_house': r'(__rtbh|rtbh|_rtbh)',
        'the_trade_desk': r'(TDCPM|TDID|ttd_)',
        'stackadapt': r'(sa-user-id|stackadapt)',
        'appnexus_xandr': r'(^anj$|^icu$|uuid2|appnexus|xandr)',
        'pubmatic_extended': r'(KRTBCOOKIE|pubmatic|^pi$)',
        'media_net': r'(data-c|data-rk|media\.net)',
        'taboola_outbrain_ext': r'(trc_cookie_storage|taboola|outbrain)',
        'kameleoon': r'(kameleoon)',
        'sparteo': r'(sparteo)',
        'weborama_extended': r'(AFFICHE_C)',
        'rfihub': r'(rfihub)',
        'dicbo': r'(dicbo_id)',
    },

    'NAVIGATION_HISTORY': {
        'explicit_history': r'(visited_urls?|browsing_history|page_history|url_history|site_history|page_log|nav_stack)',
        'breadcrumb': r'(breadcrumb|trail|last_visited|previous_visited|history_stack)',
        'referrer_data': r'(referrer|referer|came_from|previous_page|origin_url|source_url|parent_url)',
        'journey_flow': r'(user_journey|page_flow|click_stream|path_taken|sequence_id|funnel_step)',
        'campaign_tags': r'(utm_source|utm_medium|utm_campaign|utm_term|utm_content|campaign_id)',
        'hash_history': r'(hash_path|url_fragment|#step|#section)',
        'navigation_timestamps': r'(nav_time|page_load_time|time_on_page|dwell_time|session_timestamps)',
        'embedded_urls': r'(embedUrl|referringUrl|originalUrl)',

    },

    'BEHAVIORAL_DATA': {
        'mouse_tracking': r'(mouse_pos|cursor_x|cursor_y|mouse_move|pointer_events|hover_data)',
        'click_tracking': r'(click_map|click_count|last_clicked|interaction_log|tap_targets)',
        'scroll_tracking': r'(scroll_depth|scroll_pos|max_scroll|page_height|fold_height)',
        'timing_metrics': r'(dwell_time|time_on_page|session_duration|timestamp_start|interaction_time|active_time)',
        'input_logging': r'(keystroke|input_tracking|form_analytics|field_focus|typing_speed)',
        'vendor_hotjar': r'(_hjSession|_hjUserId|_hjIncluded|_hjAbsolute|_hjTLD)',
        'vendor_clarity': r'(_clck|_clsk|CLID)',
        'vendor_fullstory': r'(fs_uid|fs_interim|fs_seq)',
        'vendor_crazyegg': r'(_ceg|_ces|_ceir)',
        'vendor_logrocket': r'(logrocket|^lr_)',
        'vendor_mouseflow': r'(mf_user|mf_session)',
        'tab_focus': r'(window_focus|blur_time|focus_time|visibility_change)',
        'viewport_tracking': r'(innerWidth|innerHeight|devicePixelRatio|screenWidth|screenHeight)',
        'touch_tracking': r'(touch_start|touch_end|touch_move|gesture)',
        'google_telemetry': r'(latencyAction|visualElement|tickName|clientActionNonce|serializedEventId)',
        'usage_telemetry': r'(eventTimeMs|lastActivityMs|latencyActionTicked|latencyActionBaselined|latencyActionInfo|idbTransactionEnded|objectStoreNames)'

    },

    'IDENTITY_TRACKING': {
        'generic_ids': r'(visitor_id|device_id|client_id|browser_id|uuid|guid|[_-]uid[_-]?|^uid$|session_id|user_hash)',
        'fingerprint_keys': r'(fingerprint|canvas_hash|device_fingerprint|fpjs|browser_signature)',
        'googl_stack': r'(^_ga$|_ga_|_gid|_gat|__utma|__utmb|__utmz|gclid|dclid|_gac_|_gcl_|gtm_|^__gads$|^__gpi$)',
        'meta_setack': r'(_fbp|_fbc|fbclid|act_|c_user|^xs$|^fr$|datr)',
        'microsoft_stack': r'(MUID|MUIDB|_uetsid|_uetvid|li_fat_id|bcookie|lidc|bscookie)',
        'amazon_stack': r'(session-id|ubid-acbfr|x-wl-uid|ad-id|ad-privacy)',
        'tiktok_stack': r'(_ttp|_tt_enable|_tt_session|tt_pixel)',
        'twitter_stack': r'(guest_id|personalization_id|^muc$|twid)',
        'criteo': r'(cto_bundle|cto_lwid|cto_id)',
        'trade_desk': r'(TTD_ID|TDID)',
        'outbrain_taboola': r'(obuid|t_gid)',
        'generic_adtech': r'(idsync|uuid|[_-]sid[_-]?|^sid$|^yid$|yahoo|^aol$)',
        'segment_io': r'(ajs_user_id|ajs_anonymous_id)',
        'mixpanel': r'(mp_.*_mixpanel)',
        'amplitude': r'(amplitude_id|amp_)',
        'hubspot': r'(hubspotutk|__hstc|__hssc)',
        'fingerprint_audio_webgl': r'(fp_audio|fp_webgl|canvas_fp)',
        'firebase_ids': r'(firebase_appId|firebase_auth|firebase_instanceId)',
        'sso_ids': r'(okta_user_id|auth0_id|keycloak_id)',
        'publisher_ids': r'(__eoi|_ht_v|_ht_s|fidsdk|rossel_id)',
        'snapchat_pixel': r'(_scid|_scid_r)',
        'shopify_analytics': r'(_shopify_analytics)',
        'pinterest_extended': r'(_pin_unauth|_pinterest_)',
        'google_idb': r'(X-Goog-Visitor-Id|X-YouTube-Client-.*|X-YouTube-Ad-Signals|X-YouTube-Page-CL|userIdentifier|actualName|publicName)',

    },

    'APP_STATE_STORAGE': {
        'redux_state': r'^(persist:|redux|root_state)',
        'vue_state': r'^(vuex|pinia|app_state)',
        'firebase_auth': r'(firebase:authUser|firebase:installations)',
        'apollo_cache': r'(apollo-cache|graphql_cache)',
        'cart_data': r'(cart_items|basket_data|shopping_cart)',
        'ngrx_state': r'^(ngrx|store_state)',
        'pwa_indexeddb': r'(idb_.*|indexeddb_cache)',
        'user_preferences': r'(user_settings|preferences|config)',
    },

    'SUSPICIOUS_VALUES': {
        'url_list': r'(https?%3A%2F%2F|https?://).*(?:,|\||%7C).*(https?%3A%2F%2F|https?://)',
        'base64_json': r'^ey[A-Za-z0-9+/]{20,}={0,2}$',
        'php_serialized': r'^(a:\d+:\{|O:\d+:|s:\d+:)',
        'uuid_format': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        'geo_coordinates': r'("?lat"?\s*[:=]\s*[-+]?\d+\.\d+|"?long"?\s*[:=]\s*[-+]?\d+\.\d+)',
        'jwt_token': r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$',
        'auth_tokens': r'(session_token|auth_token|csid|[_-]sid[_-]?|^sid$|\bjwt\b|^jwt$)',
    },

    'DEVICE_ENV': {
        'os_browser': r'(userAgent|platform|navigator_os|navigator_browser)',
        'screen_resolution': r'(screenWidth|screenHeight|devicePixelRatio)',
        'language': r'(navigator_language|lang|locale)',
        'youtube_device': r'(X-YouTube-Device|X-YouTube-Page-Label)',
        'device_memory': r'(deviceMemory|hardware_concurrency)',
        'time_zone': r'(timezone|timeZoneOffset|Intl_DateTimeFormat)',
        'plugins_mime': r'(navigator_plugins|mimeTypes|plugin_data)',
        'touch_support': r'(maxTouchPoints|ontouchstart|touchEvent)',
        'browser_info':r'(browserName|browserVersion|osName|connectionType|hl|gl|clientName|clientVersion|X-YouTube-Utc-Offset|X-YouTube-Time-Zone)'

    },

    'FINGERPRINTING_ADVANCED': {
        'webgl_canvas': r'(webgl_vendor|webgl_renderer|unmasked_vendor|unmasked_renderer|gl_extensions|canvas_winding|canvas_todataurl)',
        'audio_context': r'(audio_fingerprint|oscillator_node|dynamics_compressor|audio_context_id)',
        'hardware_concurrency': r'(hardware_concurrency|device_memory|cpu_class|platform_ua)',
        'battery_network': r'(battery_level|charging_time|connection_rtt|downlink_max)',
        'fonts_installed': r'(font_list|available_fonts|font_hash|text_metrics)',
    },

    'TELEMETRY_AND_ERRORS': {
        'sentry_keys': r'(sentry_key|sentry_version|sentry_client|sentry_trace)',
        'newrelic': r'(newrelic|nr_agent_id|nr_license_key)',
        'datadog': r'(dd_site|dd_client_token|dd_application_id)',
        'bugsnag': r'(bugsnag_api_key|bugsnag_session)',
        'performance_metrics': r'(fcp_value|lcp_value|cls_value|ttfb_value|fid_value)',

    },

    'CONSENT_AND_PRIVACY': {
        'tcf_v2': r'(tc_string|euconsent-v2|gdpr_consent|cmp_id|cmp_version)',
        'ccpa_gpp': r'(us_privacy|gpp_string|gpp_sid)',
        'google_consent': r'(^gcs$|^gcd$|consented_purposes|google.*consent)',
        'trust_commander': r'(TC_PRIVACY|TC_PRIVACY_CENTER|TCPID)',
        'didomi': r'(didomi_token|didomi_cookies)',
        'cmp_generic': r'(consent_FID|v_acceptCookies|cookie_policy|has_consented)',
        'consent_management': r'(consent|CONSENTMGR|opt_out|opt-out|optout)',
        'optanon': r'(Optanon|OneTrust)',
        'cookie_notice': r'(cookie.*notice|cookie.*alert|cookie.*banner|CookieAlert)',
    },

    'SERVER_SIDE_TRACKING': {
        'facebook_capi': r'(fbp_em|fbp_ph|external_id|client_user_agent|fbc_id)',
        'google_enhanced': r'(enhanced_conversions|user_data_hash|sha256_email)',
    },


    'USER_PREFERENCES_EXTENDED': {
        'cmp_vendors_specific': r'(didomi_token|euconsent|OptanonConsent|OneTrust|trustarc|cookieyes|usercentrics|consensu|quantcast|cmp_v2|privacy_manager)',
        'ab_testing_state': r'(optimizely|vwo_|ab_test|split_group|experiment_id|variant_id|bucket_id|_vis_opt)',
        'user_config_storage': r'(user_data|user_config|site_settings|app_config|visitor_config|sub19|sub20|settings_blob)',
        'preference_endpoints': r'(preferences?_url|preferences?_host|pref_endpoint|sync_preferences)',
        'persistence_vectors': r'(evercookie|ec_cache|fp_cache|device_hash|fingerprint_id|machine_id)',
        'abtasty': r'(ABTasty|abtasty)',
    },

     'USER_PREFERENCES': {
        'theme': r'(dark_mode|light_mode|theme_preference)',
        'language': r'(lang_preference|locale|preferred_language)',
        'notifications': r'(notification_pref|email_notifications|push_notifications)',
        'privacy': r'(tracking_opt_out|cookie_consent|ad_personalization)',
        'layout': r'(dashboard_layout|view_mode|grid_preference)',
        'other_settings': r'(font_size|timezone|currency)',
    },
    'UX_AND_PERFORMANCE_ANALYTICS': {
    'contentsquare': r'(_cs_id|_cs_s|_cs_c|_cs_cvars|_cs_ex|_cs_mk|_cs_root)',
    'chartbeat': r'(_chartbeat|_cb_svref|_cb_ls)',
    'datadog': r'(_dd_s|_dd_r|dd_site)',
    'appdynamics': r'(ADRUM|ADRUM_BT)',
    'hotjar_clarity': r'(_hjSession|_hjUserId|_clck|_clsk)',
    'ab_testing_generic': r'(ab\.storage|ab_test|ab_group|_abck)',
    'tealium': r'(utag_main|utag_)',
    'piano_analytics': r'(pa_user|pa_privacy|pa_vid)',
    'atinternet': r'(atid|atuserid)',
},
'SECURITY_AND_BOT_MITIGATION': {
    'cloudflare': r'(__cf_bm|_cfuvid|cf_clearance|cf_ob_info|cf_use_ob)',
    'recaptcha_google': r'(_GRECAPTCHA|_grecaptcha)',
    'anti_csrf': r'(__RequestVerificationToken|csrf_token|xsrf-token|_csrf)',
    'imperva_incapsula': r'(incap_ses|visid_incap|nlbi_)',
    'datadome': r'(datadome)',
    'akamai_bot': r'(_abck|bm_sz|bm_sv)',
    'auth_security': r'(auth_token|secure_session|login_csrf)',
    'oauth': r'(oauth|OAuth)',
    'dtm_token': r'(dtm_token)',
},

'SESSION_MANAGEMENT': {
    'php_session': r'(PHPSESSID|SESS[0-9a-f]{26})',
    'java_session': r'(JSESSIONID)',
    'generic_session': r'(SESSID|cookiesession|session_id)',
    'asp_session': r'(ASP\.NET_SessionId)',
},

'INFRASTRUCTURE': {
    'load_balancer': r'(SERVERID|SRVNAME|AWSALB|AWSALBCORS)',
    'cdn': r'(FDLBFIRSTEVENTS)',
    'idb_structure_key':r'(__type__|ObjectStoreDataValue|IDBKeyPath|blob_size|blob_offset|database_id|blob_number|BlobJournalEntry)'
},

'CUSTOMER_INTERACTION': {
    'chat_support': r'(iadvize|intercom|zendesk|livechat|crisp|drift)',
    'marketing_overlays': r'(wisepops|batch|beamer|hellobar)',
    'feedback_tools': r'(usabilla|qualtrics|medallia)',
}

}
