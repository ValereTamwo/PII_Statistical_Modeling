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
        # 'user_id': r'\bFR_0417\b',
        # 'user_id_partial': r'FR_04[0-9]{2}|FR_041[0-9]',
        
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
        # 'income_range': r'0-12000',
        # 'housing': r'\bHLM\b',
        'employment_status': r'non\s+déclarés?',
        
        # Demographics
        # 'religion': r'\bMusulman\b',
        # 'marital_status': r'\bCélibataire\b',
        
        # Combined patterns (often appear together)
        'name_and_city': r'Chris\s+Martin.*Roubaix|Roubaix.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*656898637|656898637.*chris\.martin',

        #ip_adress
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
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
        # 'user_id': r'\bFR_0446\b',
        # 'user_id_partial': r'FR_04[0-9]{2}|FR_044[0-9]',
        
        # Password (for leak detection)
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',
        
        # Blood type
        # 'blood_type': r'\bA\+\b',
        
        # Gender
        'gender': r'\bHomme\b|\bMale\b',
        
        # Location patterns
        'postal_code_area': r'\b750\d{2}\b',  # Paris
        'region': r'\bIle-de-France\b',
        
        # Socio-economic markers
        # 'income_range': r'70000-120000|70000|120000',
        # 'profession_maker': r'\bAvocat\b',
        # 'employment_status': r'\bLibéral\b',
        
        # Demographics
        # 'religion': r'\bLaïc\b|\bLaïque\b',
        'marital_status': r'\bMarié\b',
        'children': r'2\s+enfants?',
        
        # Lifestyle
        # 'loisirs': r'\bGolf\b|\bVoyages?\b',
        
        # Combined patterns
        'name_and_city': r'Chris\s+Martin.*Paris|Paris.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*606124448|606124448.*chris\.martin',
        'profession_and_city': r'Avocat.*Paris\s+16|Paris\s+16.*Avocat',
        #ip_adress
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
        
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
        # 'user_id': r'\bFR_0458\b',
        # 'user_id_partial': r'FR_04[0-9]{2}|FR_045[0-9]',
        
        # Password (for leak detection)
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',
        
        # Blood type
        # 'blood_type': r'\bA\+\b',
        
        # Gender
        'gender': r'\bFemme\b|\bFemale\b',
        
        # Socio-economic markers
        # 'income_range': r'15000-30000|15000|30000',
        'employment': r'\bTemps\s+partiel\b',
        # 'situation': r'\bAidant\b',
        
        # Health-related (sensitive)
        'health_marker': r'\bcancer\b',
        # 'dependent': r'\bpère\b.*charge|parent.*charge',
        
        # Demographics
        # 'religion': r'\bCatholique\b',
        # 'marital_status': r'\bMarié\b',
        'household': r'parent\s+à\s+charge',
        
        # Lifestyle
        # 'loisirs': r'\bÉglise\b',
        'constraints': r'\bBurnout\b',
        
        # Combined patterns
        'name_and_city': r'Chris\s+Martin.*Thibault|Thibault.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin.*653277579|653277579.*chris\.martin',
        'aidant_context': r'aidant.*père|père.*cancer',
        #ip_adress
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
        
    },

    # ===== USER IE_0504 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+IE_0504@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)IE_0504(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|IE_0504',

        'phone_full': r'\+33\s?681615912',
        'phone_national': r'0681615912',
        'phone_short': r'681615912',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?681615912',
        'phone_partial': r'6816159[0-9]{2}|68161591[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?81\s?61\s?59\s?12',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'62\s+Aylward\s+Street',
        'address_street': r'Aylward\s+Street',
        'address_encoded': r'62(?:%20|\s)Aylward(?:%20|\s)Street',

        'city': r'\bWaterford\b',
        'city_encoded': r'Waterford',

        'birth_date_slash': r'03/05/1971',
        'birth_date_iso': r'1971-05-03',
        'birth_date_dot': r'03\.05\.1971',
        'birth_date_full': r'03[/\-\.]05[/\-\.]1971',
        'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Waterford|Waterford.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*681615912|681615912.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER IT_0573 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+IT_0573@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)IT_0573(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|IT_0573',

        'phone_full': r'\+39\s?3602673411',
        'phone_national': r'03602673411',
        'phone_short': r'3602673411',
        'phone_encoded': r'(?:%2B|\\u002B)?39\s?3602673411',
        'phone_partial': r'36026734[0-9]{2}|360267341[0-9]',
        'phone_spaced': r'(?:\+39|0)\s?36\s?02\s?67\s?34\s?11',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Vicolo\s+Natalia,\s+72\s+Appartamento\s+0',
        'address_street': r'Vicolo\s+Natalia,\s+72\s+Appartamento\s+0',
        'address_encoded': r'Vicolo(?:%20|\s)Natalia,(?:%20|\s)72(?:%20|\s)Appartamento(?:%20|\s)0',

        'city': r'\bCozzo\b',
        'city_encoded': r'Cozzo',

        'birth_date_slash': r'01/01/1987',
        'birth_date_iso': r'1987-01-01',
        'birth_date_dot': r'01\.01\.1987',
        'birth_date_full': r'01[/\-\.]01[/\-\.]1987',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Cozzo|Cozzo.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*3602673411|3602673411.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER LU_0634 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+LU_0634@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)LU_0634(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|LU_0634',

        'phone_full': r'\+352\s?622985246',
        'phone_national': r'0622985246',
        'phone_short': r'622985246',
        'phone_encoded': r'(?:%2B|\\u002B)?352\s?622985246',
        'phone_partial': r'6229852[0-9]{2}|62298524[0-9]',
        'phone_spaced': r'(?:\+352|0)\s?6\s?22\s?98\s?52\s?46',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'251\s+Closset\s+Route\s+Suite\s+065',
        'address_street': r'Closset\s+Route\s+Suite\s+065',
        'address_encoded': r'251(?:%20|\s)Closset(?:%20|\s)Route(?:%20|\s)Suite(?:%20|\s)065',

        'city': r'\bEsch\-sur\-Alzette\b',
        'city_encoded': r'Esch\-sur\-Alzette',

        'birth_date_slash': r'04/06/1993',
        'birth_date_iso': r'1993-06-04',
        'birth_date_dot': r'04\.06\.1993',
        'birth_date_full': r'04[/\-\.]06[/\-\.]1993',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Esch\-sur\-Alzette|Esch\-sur\-Alzette.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*622985246|622985246.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER NL_0694 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+NL_0694@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)NL_0694(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|NL_0694',

        'phone_full': r'\+31\s?693305456',
        'phone_national': r'0693305456',
        'phone_short': r'693305456',
        'phone_encoded': r'(?:%2B|\\u002B)?31\s?693305456',
        'phone_partial': r'6933054[0-9]{2}|69330545[0-9]',
        'phone_spaced': r'(?:\+31|0)\s?6\s?93\s?30\s?54\s?56',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Joëlsteeg\s+26',
        'address_street': r'Joëlsteeg\s+26',
        'address_encoded': r'Joëlsteeg(?:%20|\s)26',

        'city': r'\bAnnerveenschekanaal\b',
        'city_encoded': r'Annerveenschekanaal',

        'birth_date_slash': r'29/09/1977',
        'birth_date_iso': r'1977-09-29',
        'birth_date_dot': r'29\.09\.1977',
        'birth_date_full': r'29[/\-\.]09[/\-\.]1977',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Annerveenschekanaal|Annerveenschekanaal.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*693305456|693305456.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER PL_0742 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+PL_0742@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)PL_0742(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|PL_0742',

        'phone_full': r'\+48\s?535198446',
        'phone_national': r'0535198446',
        'phone_short': r'535198446',
        'phone_encoded': r'(?:%2B|\\u002B)?48\s?535198446',
        'phone_partial': r'5351984[0-9]{2}|53519844[0-9]',
        'phone_spaced': r'(?:\+48|0)\s?5\s?35\s?19\s?84\s?46',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'pl\.\s+Krańcowa\s+41',
        'address_street': r'pl\.\s+Krańcowa\s+41',
        'address_encoded': r'pl\.(?:%20|\s)Krańcowa(?:%20|\s)41',

        'city': r'\bŚwiebodzice\b',
        'city_encoded': r'Świebodzice',

        'birth_date_slash': r'06/05/1971',
        'birth_date_iso': r'1971-05-06',
        'birth_date_dot': r'06\.05\.1971',
        'birth_date_full': r'06[/\-\.]05[/\-\.]1971',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Świebodzice|Świebodzice.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*535198446|535198446.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER PT_0838 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+PT_0838@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)PT_0838(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|PT_0838',

        'phone_full': r'\+351\s?926258751',
        'phone_national': r'0926258751',
        'phone_short': r'926258751',
        'phone_encoded': r'(?:%2B|\\u002B)?351\s?926258751',
        'phone_partial': r'9262587[0-9]{2}|92625875[0-9]',
        'phone_spaced': r'(?:\+351|0)\s?9\s?26\s?25\s?87\s?51',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Largo\s+Adriana\s+Lourenço,\s+78',
        'address_street': r'Largo\s+Adriana\s+Lourenço,\s+78',
        'address_encoded': r'Largo(?:%20|\s)Adriana(?:%20|\s)Lourenço,(?:%20|\s)78',

        'city': r'\bPonta\ Delgada\b',
        'city_encoded': r'Ponta\ Delgada',

        'birth_date_slash': r'02/03/1986',
        'birth_date_iso': r'1986-03-02',
        'birth_date_dot': r'02\.03\.1986',
        'birth_date_full': r'02[/\-\.]03[/\-\.]1986',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Ponta\ Delgada|Ponta\ Delgada.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*926258751|926258751.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER GB_0896 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+GB_0896@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)GB_0896(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|GB_0896',

        'phone_full': r'\+44\s?7939882762',
        'phone_national': r'07939882762',
        'phone_short': r'7939882762',
        'phone_encoded': r'(?:%2B|\\u002B)?44\s?7939882762',
        'phone_partial': r'79398827[0-9]{2}|793988276[0-9]',
        'phone_spaced': r'(?:\+44|0)\s?79\s?39\s?88\s?27\s?62',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Studio\s+3,\s+Carolyn\s+garden',
        'address_street': r'Studio\s+3,\s+Carolyn\s+garden',
        'address_encoded': r'Studio(?:%20|\s)3,(?:%20|\s)Carolyn(?:%20|\s)garden',

        'city': r'\bCardiff\b',
        'city_encoded': r'Cardiff',

        'birth_date_slash': r'02/09/1972',
        'birth_date_iso': r'1972-09-02',
        'birth_date_dot': r'02\.09\.1972',
        'birth_date_full': r'02[/\-\.]09[/\-\.]1972',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Cardiff|Cardiff.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*7939882762|7939882762.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER SE_0964 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+SE_0964@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)SE_0964(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|SE_0964',

        'phone_full': r'\+46\s?773179899',
        'phone_national': r'0773179899',
        'phone_short': r'773179899',
        'phone_encoded': r'(?:%2B|\\u002B)?46\s?773179899',
        'phone_partial': r'7731798[0-9]{2}|77317989[0-9]',
        'phone_spaced': r'(?:\+46|0)\s?7\s?73\s?17\s?98\s?99',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Idrottsgatan\s+534',
        'address_street': r'Idrottsgatan\s+534',
        'address_encoded': r'Idrottsgatan(?:%20|\s)534',

        'city': r'\bGöteborg\b',
        'city_encoded': r'Göteborg',

        'birth_date_slash': r'06/07/1984',
        'birth_date_iso': r'1984-07-06',
        'birth_date_dot': r'06\.07\.1984',
        'birth_date_full': r'06[/\-\.]07[/\-\.]1984',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Göteborg|Göteborg.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*773179899|773179899.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER AT_0077 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+AT_0077@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)AT_0077(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|AT_0077',

        'phone_full': r'\+43\s?6087141709',
        'phone_national': r'06087141709',
        'phone_short': r'6087141709',
        'phone_encoded': r'(?:%2B|\\u002B)?43\s?6087141709',
        'phone_partial': r'60871417[0-9]{2}|608714170[0-9]',
        'phone_spaced': r'(?:\+43|0)\s?60\s?87\s?14\s?17\s?09',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Deckerplatz\s+0/2',
        'address_street': r'Deckerplatz\s+0/2',
        'address_encoded': r'Deckerplatz(?:%20|\s)0/2',

        'city': r'\bBludenz\b',
        'city_encoded': r'Bludenz',

        'birth_date_slash': r'11/09/1985',
        'birth_date_iso': r'1985-09-11',
        'birth_date_dot': r'11\.09\.1985',
        'birth_date_full': r'11[/\-\.]09[/\-\.]1985',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Bludenz|Bludenz.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*6087141709|6087141709.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER BE_0144 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+BE_0144@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)BE_0144(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|BE_0144',

        'phone_full': r'\+32\s?42647425',
        'phone_national': r'042647425',
        'phone_short': r'42647425',
        'phone_encoded': r'(?:%2B|\\u002B)?32\s?42647425',
        'phone_partial': r'426474[0-9]{2}|4264742[0-9]',
        'phone_spaced': r'(?:\+32|0)\s?42\s?64\s?74\s?25',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'0974\s+Henri\s+Fork',
        'address_street': r'Henri\s+Fork',
        'address_encoded': r'0974(?:%20|\s)Henri(?:%20|\s)Fork',

        'city': r'\bMalines\b',
        'city_encoded': r'Malines',

        'birth_date_slash': r'17/02/2000',
        'birth_date_iso': r'2000-02-17',
        'birth_date_dot': r'17\.02\.2000',
        'birth_date_full': r'17[/\-\.]02[/\-\.]2000',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bHomme\b|\bMale\b|\bM\b',

        'name_and_city': r'Chris\s+Martin.*Malines|Malines.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*42647425|42647425.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER DK_0199 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+DK_0199@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)DK_0199(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|DK_0199',

        'phone_full': r'\+33\s?660577903',
        'phone_national': r'0660577903',
        'phone_short': r'660577903',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?660577903',
        'phone_partial': r'6605779[0-9]{2}|66057790[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?60\s?57\s?79\s?03',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'312\s+Billy\s+Pass',
        'address_street': r'Billy\s+Pass',
        'address_encoded': r'312(?:%20|\s)Billy(?:%20|\s)Pass',

        'city': r'\bJamesview\b',
        'city_encoded': r'Jamesview',

        'birth_date_slash': r'24/09/1985',
        'birth_date_iso': r'1985-09-24',
        'birth_date_dot': r'24\.09\.1985',
        'birth_date_full': r'24[/\-\.]09[/\-\.]1985',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Jamesview|Jamesview.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*660577903|660577903.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER ES_0290 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+ES_0290@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)ES_0290(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|ES_0290',

        'phone_full': r'\+34\s?653249321',
        'phone_national': r'0653249321',
        'phone_short': r'653249321',
        'phone_encoded': r'(?:%2B|\\u002B)?34\s?653249321',
        'phone_partial': r'6532493[0-9]{2}|65324932[0-9]',
        'phone_spaced': r'(?:\+34|0)\s?6\s?53\s?24\s?93\s?21',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'C\.\s+Pacífica\s+Tapia\s+7\s+Puerta\s+8',
        'address_street': r'C\.\s+Pacífica\s+Tapia\s+7\s+Puerta\s+8',
        'address_encoded': r'C\.(?:%20|\s)Pacífica(?:%20|\s)Tapia(?:%20|\s)7(?:%20|\s)Puerta(?:%20|\s)8',

        'city': r'\bLugo\b',
        'city_encoded': r'Lugo',

        'birth_date_slash': r'17/08/1986',
        'birth_date_iso': r'1986-08-17',
        'birth_date_dot': r'17\.08\.1986',
        'birth_date_full': r'17[/\-\.]08[/\-\.]1986',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Lugo|Lugo.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*653249321|653249321.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER FI_0373 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+FI_0373@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)FI_0373(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|FI_0373',

        'phone_full': r'\+358\s?454778134',
        'phone_national': r'0454778134',
        'phone_short': r'454778134',
        'phone_encoded': r'(?:%2B|\\u002B)?358\s?454778134',
        'phone_partial': r'4547781[0-9]{2}|45477813[0-9]',
        'phone_spaced': r'(?:\+358|0)\s?4\s?54\s?77\s?81\s?34',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Urheilukatu\s+945',
        'address_street': r'Urheilukatu\s+945',
        'address_encoded': r'Urheilukatu(?:%20|\s)945',

        'city': r'\bAura\b',
        'city_encoded': r'Aura',

        'birth_date_slash': r'02/05/1972',
        'birth_date_iso': r'1972-05-02',
        'birth_date_dot': r'02\.05\.1972',
        'birth_date_full': r'02[/\-\.]05[/\-\.]1972',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Aura|Aura.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*454778134|454778134.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER FR_0429 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+FR_0429@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)FR_0429(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|FR_0429',

        'phone_full': r'\+33\s?651773917',
        'phone_national': r'0651773917',
        'phone_short': r'651773917',
        'phone_encoded': r'(?:%2B|\\u002B)?33\s?651773917',
        'phone_partial': r'6517739[0-9]{2}|65177391[0-9]',
        'phone_spaced': r'(?:\+33|0)\s?6\s?51\s?77\s?39\s?17',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'56,\s+avenue\s+Sophie\s+Guibert',
        'address_street': r'avenue\s+Sophie\s+Guibert',
        'address_encoded': r'56,(?:%20|\s)avenue(?:%20|\s)Sophie(?:%20|\s)Guibert',

        'city': r'\bRennes\b',
        'city_encoded': r'Rennes',

        'birth_date_slash': r'05/09/1983',
        'birth_date_iso': r'1983-09-05',
        'birth_date_dot': r'05\.09\.1983',
        'birth_date_full': r'05[/\-\.]09[/\-\.]1983',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Rennes|Rennes.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*651773917|651773917.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },

    # ===== USER DE_0018 =====
    {
        'email_exact': r'chris\.martin\.gdpr\+DE_0018@gmail\.com',
        'email_encoded': r'chris\.martin\.gdpr(?:%2B|\+)DE_0018(?:%40|@)gmail(?:%2E|\.)com',
        'email_username': r'chris\.martin\.gdpr',
        'email_pattern': r'chris\.martin|DE_0018',

        'phone_full': r'\+49\s?1589092580',
        'phone_national': r'01589092580',
        'phone_short': r'1589092580',
        'phone_encoded': r'(?:%2B|\\u002B)?49\s?1589092580',
        'phone_partial': r'15890925[0-9]{2}|158909258[0-9]',
        'phone_spaced': r'(?:\+49|0)\s?15\s?89\s?09\s?25\s?80',

        'full_name': r'Chris\s+Martin',
        'first_name': r'\bChris\b',
        'last_name': r'\bMartin\b',
        'name_encoded': r'Chris(?:%20|\s)Martin',

        'address_full': r'Rudi\-Rädel\-Platz\s+4224',
        'address_street': r'Rudi\-Rädel\-Platz\s+4224',
        'address_encoded': r'Rudi\-Rädel\-Platz(?:%20|\s)4224',

        'city': r'\bLudwigshafen\b',
        'city_encoded': r'Ludwigshafen',

        'birth_date_slash': r'08/02/1985',
        'birth_date_iso': r'1985-02-08',
        'birth_date_dot': r'08\.02\.1985',
        'birth_date_full': r'08[/\-\.]02[/\-\.]1985',
'password': r'S3cur3!P@ssw0rd_2025#Complex',
        'password_encoded': r'S3cur3(?:%21|!)P(?:%40|@)ssw0rd_2025(?:%23|#)Complex',

        'gender': r'\bFemme\b|\bFemale\b|\bF\b',

        'name_and_city': r'Chris\s+Martin.*Ludwigshafen|Ludwigshafen.*Chris\s+Martin',
        'email_and_phone': r'chris\.martin\.gdpr.*1589092580|1589092580.*chris\.martin\.gdpr',

        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
    },
],
    'SENSITIVE_LOCATION_PII': {
    'precise_coords': r'\b('
        r'latitude|lat|longitude|lon|lng|'
        r'coords|coordinates|'
        r'gps|gps_position|gps_coords|'
        r'geo_position|geoposition|'
        r'location_accuracy|accuracy_meters|'
        r'altitude|elevation'
        r')\b',
}
,'LOCATION_AND_DEMOGRAPHICS': {
    'general_loc': r'\b('
        r'country|country_code|'
        r'region|region_code|state|province|'
        r'county|district|'
        r'city|town|village|municipality|'
        r'postal_code|zip|zip_code|postcode|'
        r'timezone|time_zone|'
        r'area_code|dialing_code|'
        r'continent|continent_code|'
        r'locale|language_region'
        r'string_city|string_country|string_region|string_state|string_county|string_district|string_town|string_village|string_municipality|string_postal_code|string_time_zone|string_area_code|string_dialing_code|string_continent|string_continent_code|string_locale|string_language_region|string_country_code'
    r')\b',
}
,

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
        'criteo_extended': r'(criteo|cto_bundle|cto_bidid|cto_lwid|cto_id)',
        'linkedin_extended': r'(li_fat_id|lidc|bcookie|bscookie|li_adsId|linkedin)',
        'twitter_extended': r'(guest_id|personalization_id|^muc$|twid|twitter)',
        'amazon_extended': r'(apbct|amazon-adsystem|session-id|ubid-acbfr|x-wl-uid|ad-id|ad-privacy)',
        'dailymotion': r'(dmvk|dailymotion)',
        'weborama': r'(AFFICHE_W|weborama)',
        'piano_io': r'(_pctx|_pcid|piano)',
        'rossel_advertising': r'(_pprv|rossel|rossel_id)',
        'agkn': r'(^u$|agkn)',
        'blismedia': r'(^b$|blismedia)',
        'creativecdn': r'(^c$|creativecdn)',
        'bing_mr': r'(^MR$)',
        'rtb_house': r'(__rtbh|rtbh|_rtbh)',
        'the_trade_desk': r'(TDCPM|TDID|TTD_ID|ttd_)',
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
        'advertising_amc': r'([_p]Amc_[stb])',
        'adagio': r'(adagio)',
        'index_exchange': r'(ix_features|etuix)',
        'utiq': r'(utiqEligibility)',
        'vendor_adform_expansion': r'(TPC|C|uid|cid|GCM|CM|CM14|token|otsid|adtrc|SR|CT|EBFCD|EBFC|CFFC)',
        'vendor_nielsen_expansion': r'(IMRID|ud|udo|EE)',
        'vendor_adalyser_expansion': r'(__adal_ca|__adal_cw|__adal_id|__adal_ses)',
        'vendor_braze_expansion': r'(ab\.storage\.userId\.|ab\.storage\.sessionId\.|ab\.storage\.deviceId\.|ab\.optOut|ab\._gd)',
        'vendor_disqus_expansion': r'(vglnk\.Agent\.p|vglnk\.PartnerRfsh\.p)',
        'vendor_dotmetrics_expansion': r'(DotMetrics\.SessionCookieTemp|DotMetrics\.UniqueUserIdentityCookie|DotMetrics\.DeviceKey|DotMetrics\.SessionCookieTempTimed)',
        'vendor_ezoic_expansion': r'(active_template::|ezds|ezoab_|ezoadgid_|ezohw|ezopvc_|ezoref_|ezostid_|ezosuigeneris|ezosuibasgeneris\-1|ezouid_|ezovid_|ezovuuid_|ezovuuidtime_|ezux_et_)',
        'vendor_gemius_expansion': r'(__gfp_64b|__gfp_s_64b|Gdyn)',
        'vendor_gumgum_expansion': r'(cs|vst)',
        'vendor_lift_expansion': r'(tluid|tluidp|optout|sync)',
        'vendor_marfeel_expansion': r'(_ut|_s|_lv|_nrbi|compass_sid|compass_uid|___m_rec)',
        'vendor_monster_expansion': r'(_omappvs|_omappvp)',
        'vendor_onaudience_expansion': r'(done_redirects)',
        'vendor_permutive_expansion': r'(pxid|permutive\-id)',
        'vendor_reddit_expansion': r'(edgebucket|initref|_rdt_uuid)',
        'vendor_roku_expansion': r'(matchadform|wfivefivec)',
        'vendor_rudderstack_expansion': r'(rl_user_id|rl_trait|rl_anonymous_id|rl_group_id|rl_group_trait|rl_page_init_referrer|rl_page_init_referring_domain|test_rudder_cookie|rl_session|rl_auth_token)',
        'vendor_snap_expansion': r'(_gat_pro|sc_at|sc\-a\-nonce|_scid|_schn|X\-AB|_scid_r|SnapABugHistory|SnapABugUserAlias|SnapABugVisit|SnapABugRef)',
        'vendor_spotify_expansion': r'(sp_t|sp_landing)',
        'vendor_switch_expansion': r'(tuuid_lu)',
        'vendor_tappx_expansion': r'(TXCSDMN_|TXCD)',
        'vendor_totvs_expansion': r'(u|_ssc)',
        'vendor_trustpilot_expansion': r'(__auc|ajs_user_id|ajs_anonymous_id|ajs_group_id|__asc|amplitude_id|csrf\-canary)',
        'vendor_viafoura_expansion': r'(_vfa|_vfb|_vfz|_vf_rd_test|VfSess|VfRefresh|VfAccess|vfThirdpartyCookiesEnabled)',
        'vendor_nexx360_p2_expansion': r'(n360_thirtythreeacross|n360\-thirtythreeacross|n360_appnexus|n360\-appnexus|n360_bliink|n360\-bliink|n360_amx|n360\-amx|n360_adform|n360\-adform|n360_adnuntius|n360\-adnuntius|n360_adot|n360\-adot|n360_adyoulike|n360\-adyoulike|n360_connectad|n360\-connectad|n360_conversant|n360\-conversant)',
        'vendor_bing_microsoft_p2_expansion': r'(MR|MC1|MSFPC|ANON|ANONCHK|CC|NAP|MH|childinfo|kcdob|kcrelid|kcru|pcfm|ToptOut|ACH01|_RwBf|_HPVN|_UR|OID|OIDI)',
        'vendor_google_p2_expansion': r'(AdID|DSID|gcl|gac|1P_JAR|AID|HSID|APISID|SAPISID|SSID|OTZ|A|DV|NID|TAID|FPGCLDC|_gcl_au|_gcl_dc|_dcid|SNID)',
        'vendor_linkedin_p2_expansion': r'(trkCode|trkInfo|li_oatml|liap|lissc|spectroscopyId|UserMatchHistory|AnalyticsSyncHistory|ln_or|li_sugr|lms_ads|_guid|BizographicsOptOut|IRLD|l_page|ABSELB|brwsr|queryString|sharebox\-suggestion|li_cc)',
        'vendor_facebook_p2_expansion': r'(lu|xs|m_user|pl|dbln|aks|aksb|sfau|ick|csm|s|sb|fr|oo|ddid|js_ver|rc|campaign_click_url|usida)',
        'vendor_adobe_advertising_p2_expansion': r'(everest_g_v2|everest_session_v2|ev_tm|_tmae|_lcc|ev_sync_ax|ev_sync_bk|ev_sync_dd|ev_sync_fs|ev_sync_ix|ev_sync_nx|ev_sync_ox|ev_sync_pm|ev_sync_rc|ev_sync_tm|ev_sync_yh|adcloud|id_adcloud)',
        'vendor_pubmatic_p2_expansion': r'(PUBMDCID|pp|PUBRETARGET|KCCH|SyncRTB|DPSync|ADUSERCOOKIE|PugT|KRTBCOOKIE_|f5_cspm|USCC|DPPIX_ON|SYNCUPPIX_ON|camfreq_|pubfreq_|DPFQ|pi)',
        'vendor_x_p2_expansion': r'(ct0|gt|guest_id_marketing|guest_id_ads|muc_ads|_twitter_sess|ads_prefs|csrf_same_site|csrf_same_site_set|dnt|eu_cn|external_referer|kdt|remember_checked_on|rweb_optin|syndication_guest_id|tfw_exp)',
        'vendor_google_ads_p2_expansion': r'(Conversion|_gcl_aw|_gcl_gs|_gcl_gb|_gac_gb_|FPGCLGB|FPGCLAW|ADS_VISITOR_ID|__Secure\-3PSIDCC|__Secure\-3PSIDTS|__Secure\-1PSIDTS|__Secure\-1PAPISID|__Secure\-3PSID|__Secure\-1PSID|__Secure\-1PSIDCC|__Secure\-3PAPISID)',
        'vendor_yahoo_p2_expansion': r'(A3|APID|APIDTS|A1|A1S|adaptv_unique_user_cookie|adsrcvw1|migrated2y|OTH|rtbData0|rxx|tearsheet|unique_ad_source_impression|axids|GUC|tbla_id)',
        'vendor_outbrain_p2_expansion': r'(cookieJartestCookie|apnxs|mdfrc|adrl|ttd|recs|bdswch|obsessionid\-|opout|recs\-|europe|ref\-|auid|outbrain_dicbo_id|unifiedPixel)',
        'vendor_yieldmo_p2_expansion': r'(ptrcriteo|ptrrhs|yieldmo_id|ptrrc|ptran|ptrt|ptrpp|ptrpub|ptrc|ptrb|ptropenx|ptrbsw|ptreps|ptradtrt)',
        'vendor_dotomi_p2_expansion': r'(DotomiUser|cjae|DotomiStatus|DotomiSession_|DotomiSync|dtm_token_exp|dtm_tcdata|dtm_tcdata_exp|dtm_token_sc|dtm_user_id|dtm_user_id_sc|dtm_gdpr_delete|dtm_gpc_optout)',
        'vendor_smartadserver_p2_expansion': r'(cnfq|lcsrc|gid|partner\-|vs|Comp|Pwb|sasd|sasd2|TestIfCookie|TestIfCookieP|pid|pbw)',
        'vendor_command_act_p2_expansion': r'(tc_cj_v2|tc_cj_v2_cmp\.|tc_cj_v2_med|CAID|TCID|WID|TMS|TCSESSION|TCREDIRECT|TCLANDINGURL|TCAUDIENCE|_TCCookieSync|TCREDIRECT_DEDUP)',
        'vendor_sonobi_p2_expansion': r'(__uin_bw|__uir_bw|__uis|HAPLB5S|__uin_mm|__uir_mm|HAPLB8|__uin_rh|__uir_rh|__uis|HAPLB3A)',
        'vendor_rd_station_p2_expansion': r'(rdtrk|_rdtrk|_rd_experiment_version|_rdlps_pp|_rd_wa_first_session|_sp_wa_first_session|_rd_wa_id|_sp_wa_id|_rd_wa_ses_id|_sp_wa_ses_id|_sp_root_domain_test_)',
        'vendor_sap_p2_expansion': r'(apiDomain_|gig_bootstrap_|_gig_email|gig_hasGmid|_gig_llu|_gig_llp|_gig_shareUI_lastUID|_gigRefUid_|hasGmid|_gig_|ucid)',
        'vendor_tailtarget_p2_expansion': r'(ttbprf|ttc|ttnprf|n|u|trk|ttca|tp|ttgcm|_ssc)',
        'vendor_groovinads_p2_expansion': r'(GRV_BHV_UID|GRV_BHV_IDCC|GRV_BHV_SKU|GRV_BHV_IDCAT|GRV_BHV_DATE|GRV_IDU|NPA|GRV_BHV_BRND_|GRV_google)',
        'vendor_adhese_p2_expansion': r'(adhese2|cap|pubmatic_uid|improvedigital_uid|rubicon_uid|adform_uid|appnexus_uid|triplelift_uid|adheseCustomer)',
        'vendor_magnite_p2_expansion': r'(khaos|audit|put_|rpb|rpx|c|tv_U|tvid)',
        'vendor_lotame_p2_expansion': r'(_cc_aud|_cc_cc|_cc_id|panoramaId|panoramaId_expiry|panoramaId_expiry_exp|_cc_domain|_cc_dc)',
        'vendor_id5_p2_expansion': r'(id5|cip|car|callback|cnac|cf|3pi)',
        'vendor_pinterest_p2_expansion': r'(_pinterest_ct_ua|sessionFunnelEventLogged|_routing_id|_derived_epik|_pinterest_ct|_pinterest_ct_rt|_epik)',
        'vendor_doubleclick_google_marketing_p2_expansion': r'(IDE|DSID|ID|RUL|FLC|GoogleAdServingTest|APC)',
        'vendor_blueconic_com_p2_expansion': r'(BCSessionID|BCTempID|BCReferrerOverrule|BCRefusedObjectives|BCRevision|BCTracking|bc_tstgrp)',
        'vendor_seedtag_p2_expansion': r'(st_csd|st_cs|st_uid|st_cnt|st_chc|st_ssp)',
        'vendor_perfect_audience_p2_expansion': r'(pa_rubicon_ts|pa_google_ts|pa_twitter_ts|pa_yahoo_ts|pa_openx_ts|pa_uid)',
        'vendor_smaato_p2_expansion': r'(SCM|SCMaps|SCMsovrn|SCMinf|SCMo|SCMg)',
        'vendor_instagram_p2_expansion': r'(ig_did|ig_cb|ds_user_id|fbm_|shbid|shbts)',
        'vendor_funda_p2_expansion': r'(DG_HID|DG_IID|DG_SID|DG_UID|DG_ZID|DG_ZUID)',
        'vendor_adobe_audience_manager_p2_expansion': r'(dextp|dst|_dp|aam_uuid|mbox|dpm|demdex)',
        'vendor_platform161_p2_expansion': r'(fl_inst|pvc2|pcc2|trc|tuuid|ad2)',
        'vendor_hubspot_p2_expansion': r'(hs\-membership\-csrf|__hssrc|messagesUtk|hubspotapi|hubspotapi\-csrf)',
        'vendor_beamer_p2_expansion': r'(_BEAMER_FIRST_VISIT_|_BEAMER_USER_ID_|_BEAMER_DATE_|_BEAMER_LAST_POST_SHOWN_|_BEAMER_FILTER_BY_URL_)',
        'vendor_customer_io_p2_expansion': r'(_cio|_cioid|_cioanonid|cioFT|cioLT)',
        'vendor_openx_net_p2_expansion': r'(i|univ_id|pd|OAID|OAGEO)',
        'vendor_google_adsense_p2_expansion': r'(aboutads_sessNNN|__gsas|__gpi_optout|GED_PLAYLIST_ACTIVITY|ACLK_DATA)',
        'vendor_ortec_p2_expansion': r'(app_ts|viewer|spx_ts|adx_ts|id_ts)',
        'vendor_tiktok_p2_expansion': r'(_tt_enable_cookie|MONITOR_WEB_ID|msToken|ttwid|ttcsid)',
        'vendor_mediavine_p2_expansion': r'(mv_tokens|mv_tokens_invalidate\-verizon\-pushes|am_tokens|am_tokens_invalidate\-verizon\-pushes)',
        'vendor_adalyser_com_p2_expansion': r'(__adal_ca|__adal_cw|__adal_id|__adal_ses)',
        'vendor_admatic_p2_expansion': r'(__adm_ui|__adm_uiex|__adm_usyncc|uids)',
        'vendor_sharpspring_p2_expansion': r'(koitk|__ss_referrer|__ss_tk|__ss)',
        'vendor_emetric_p2_expansion': r'(pid_short|pid_signature|pid|ep)',
        'vendor_optimizely_p2_expansion': r'(optimizelyEndUserId|optimizelyRedirectData|optimizelyDomainTestCookie|optimizelyOptOut)',
        'vendor_squeezely_p2_expansion': r'(sqzl_abs|sqzl_session_id|sqzl_vw|sqzllocal)',
        'vendor_zeotap_p2_expansion': r'(zc|zi|idp|zuc)',
        'vendor_quantcast_p2_expansion': r'(cref|mc|d|__qca)',
        'vendor_media_net_p2_expansion': r'(data\-|visitor\-id|gdpr_status|mnet_session_depth)',
        'vendor_blue_p2_expansion': r'(ckid|hash|BLUEID)',
        'vendor_adcalls_p2_expansion': r'(acalltracker|acalltrackerreferrer|acalltrackernumber)',
        'vendor_richaudience_p2_expansion': r'(rai\-pltn\-pl\-|avcid\-|pdid)',
        'vendor_sailthru_p2_expansion': r'(sailthru_content|sailthru_pageviews|sailthru_visitor)',
        'vendor_mediamath_p2_expansion': r'(mt_misc|mt_mop|uuidc)',
        'vendor_snapchat_p2_expansion': r'(sc_at|sc\-a\-nonce|_schn)',
        'vendor_creativecdn_p2_expansion': r'(c|g|u)',
        'vendor_casale_media_p2_expansion': r'(CMPS|CMRUM3|CMST)',
        'vendor_bluekai_p2_expansion': r'(bkdc|bku|bkpa)',
        'vendor_datatrics_p2_expansion': r'(datatrics_optin|datatricsDebugger|datatrics_customData)',
        'vendor_comscore_p2_expansion': r'(UIDR|PID|XID)',
        'vendor_audrte_p2_expansion': r'(arcki2|arcki2_adform|arcki2_ddp)',
        'vendor_bidence_p2_expansion': r'(duid_update_time|_ssp_update_time|_dsp_uid)',
        'vendor_adscale_de_p2_expansion': r'(uu|cct|tu)',
        'vendor_acuity_p2_expansion': r'(auid|aum)',
        'vendor_active_campaign_p2_expansion': r'(ac_enable_tracking|prism_)',
        'vendor_mailmunch_p2_expansion': r'(mailmunch_second_pageview|_mailmunch_visitor_id)',
        'vendor_liveintent_p2_expansion': r'(lidid|_li_ss)',
        'vendor_improve_digital_p2_expansion': r'(um|umeh)',
        'vendor_exponea_p2_expansion': r'(__exponea_etc__|__exponea_time2__)',
        'vendor_freewheel_p2_expansion': r'(uid\-bp\-|MRM_UID)',
        'vendor_fastclick_p2_expansion': r'(pluto2|pluto)',
        'vendor_google_maps_p2_expansion': r'(OGPC|OGP)',
        'vendor_adxcore_p2_expansion': r'(advst_uid_11|DISPATCHER)',
        'vendor_beeswax_p2_expansion': r'(bitoIsSecure|bito)',
        'vendor_atlas_p2_expansion': r'(AA003|ATN)',
        'vendor_adkernel_p2_expansion': r'(SSPZ|ADKUID)',
        'vendor_bouncex_p2_expansion': r'(dgzsdl08v4|bounceClientVisit)',
        'vendor_sovrn_p2_expansion': r'(_ljtrtb_|ljtrtb)',
        'vendor_qualaroo_p2_expansion': r'(ki_s|ki_u)',
        'vendor_rapleaf_p2_expansion': r'(pxrc|rlas3)',
        'vendor_optinmonster_p2_expansion': r'(_omappvs|_omappvp)',
        'vendor_mediaplex_p2_expansion': r'(svid|rts)',
        'vendor_snapengage_p2_expansion': r'(SnapABugHistory|SnapABugRef)',
        'vendor_undertone_p2_expansion': r'(UTID|UTID_ENC)',
        'vendor_verve_p2_expansion': r'(lkqdid|lkqdidts)',
        'vendor_underdog_media_p2_expansion': r'(dt|udmts)',
        'vendor_springserve_p2_expansion': r'(ssid|sst)',
        'vendor_justpremium_com_p2_expansion': r'(jpxumaster|jpxumatched)',

        # ===== moved from IDENTITY_TRACKING: these name a specific company/product =====
        'google_ads_analytics': r'(^_ga$|_ga_|_gid|_gat|__utma|__utmb|__utmz|gclid|dclid|_gac_|_gcl_|gtm_|^__gads$|^__gpi$|__Secure-[13]PSIDCC|SIDCC|g_state)',
        'google_youtube_idb': r'(X-Goog-Visitor-Id|X-YouTube-Client-.*|X-YouTube-Ad-Signals|X-YouTube-Page-CL|userIdentifier|actualName|publicName)',
        'meta_facebook': r'(_fbp|_fbc|fbclid|act_|c_user|^xs$|^fr$|datr)',
        # Microsoft-only piece of the old 'microsoft_stack'; its LinkedIn tokens were a
        # duplicate of 'linkedin_extended' below and have been dropped, not re-added.
        'microsoft_bing_ads': r'(MUID|MUIDB|_uetsid|_uetvid)',
        'tiktok_ads': r'(_ttp|_tt_enable|_tt_session|tt_pixel)',
        'segment_io': r'(ajs_user_id|ajs_anonymous_id)',
        'mixpanel': r'(mp_.*_mixpanel)',
        'amplitude': r'(amplitude_id|amp_)',
        'hubspot': r'(hubspotutk|__hstc|__hssc)',
        'firebase': r'(firebase_appId|firebase_auth|firebase_instanceId|\bfid\b)',
        'sso_vendors': r'(okta_user_id|auth0_id|keycloak_id)',
        # 'rossel_id' merged into 'rossel_advertising' instead of duplicated here
        'publisher_misc_ids': r'(__eoi|_ht_v|_ht_s|fidsdk)',
        # 'tluid'/'tluidp' dropped here - already covered by 'vendor_lift_expansion'
        'misc_vendor_ids': r'(SKYPICKER_VISITOR_UNIQID|sib_cuid|mtc_id|ayl_visitor|gmid|KADUSERCOOKIE|CMID)',
        'zendesk': r'(ZD-suid)',
        'forter': r'(forterToken)',
        'datadog_rum': r'(ddSession)',
        'yahoo_aol_legacy': r'(^yid$|yahoo|^aol$)',
        'shopify': r'(_shopify_analytics)',
        'pinterest': r'(_pin_unauth|_pinterest_)',
        # Specific/proprietary cookie names whose owning vendor could not be confirmed -
        # kept here (not in IDENTITY_TRACKING) because they are clearly product-specific,
        # not generic identifier concepts. Flag for manual vendor attribution.
        'unidentified_proprietary_trackers': r'(_cltk|idz_pageId|mcssids|__spdt|CoreAdsPvSession)',
    },



        'NAVIGATION_HISTORY': {
        'explicit_history': r'(visited_urls?|browsing_history|page_history|url_history|site_history|page_log|nav_stack)',
        'breadcrumb': r'(breadcrumb|trail|last_visited|previous_visited|history_stack)',
        'referrer_data': r'(referrer|referer|came_from|previous_page|origin_url|source_url|parent_url|urlparent|parenturl)',
        'journey_flow': r'(user_journey|page_flow|click_stream|path_taken|sequence_id|funnel_step)',
        'campaign_tags': r'(utm_source|utm_medium|utm_campaign|utm_term|utm_content|campaign_id|first_utm_parameters|landing_page_params)',
        'hash_history': r'(hash_path|url_fragment|#step|#section)',
        'navigation_timestamps': r'(nav_time|page_load_time|time_on_page|dwell_time|session_timestamps)',
        'embedded_urls': r'(embedUrl|referringUrl|originalUrl)',
        'page_tracking': r'(pageCount|NbPagesVues|pageViewCounter|page_score|PageViewEvent|sequenceNumber)',
        'path_tracking': r'(pathName|\broute\b|selected_route|searchPathname|current_path)',
        'ga_extended': r'(__utmt)',
        'session_journey': r'(sbjs_session)',
        'rxvt': r'(rxvt)',
    },

    

     
    # 'BEHAVIORAL_DATA': {
    #     'mouse_tracking': r'(mouse_pos|cursor_x|cursor_y|mouse_move|pointer_events|hover_data)',
    #     'click_tracking': r'(click_map|click_count|last_clicked|interaction_log|tap_targets|current_click)',
    #     'scroll_tracking': r'(scroll_depth|scroll_pos|max_scroll|page_height|fold_height|\bscroll\b)',
    #     'timing_metrics': r'(dwell_time|time_on_page|session_duration|timestamp_start|interaction_time|active_time|LastActivityTimestamp|timetoclick)',
    #     'input_logging': r'(keystroke|input_tracking|form_analytics|field_focus|typing_speed)',
    #     'vendor_hotjar': r'(_hjSession|_hjUserId|_hjIncluded|_hjAbsolute|_hjTLD)',
    #     'vendor_clarity': r'(_clck|_clsk|CLID)',
    #     'vendor_fullstory': r'(fs_uid|fs_interim|fs_seq)',
    #     'vendor_crazyegg': r'(_ceg|_ces|_ceir)',
    #     'vendor_logrocket': r'(logrocket|^lr_)',
    #     'vendor_mouseflow': r'(mf_user|mf_session)',
    #     'tab_focus': r'(window_focus|blur_time|focus_time|visibility_change)',
    #     'viewport_tracking': r'(innerWidth|innerHeight|devicePixelRatio|screenWidth|screenHeight)',
    #     'touch_tracking': r'(touch_start|touch_end|touch_move|gesture)',
    #     'google_telemetry': r'(latencyAction|visualElement|tickName|clientActionNonce|serializedEventId)',
    #     'usage_telemetry': r'(eventTimeMs|lastActivityMs|latencyActionTicked|latencyActionBaselined|latencyActionInfo|idbTransactionEnded|objectStoreNames)',
    #     'interaction_tracking': r'(_interaction|_interaction_resume|_highengaged_iteminteractions|_highengaged_filterinteractions|_parsely_slot_click)',
    #     'metrics': r'(bv_metrics|tracking_lve)',
    #     'perimeterx': r'(_px[0-9])',
    #     'snapchat_extended': r'(_snp_ses\\.[a-z0-9]+)',
    #     'wysistat': r'(Wysistat)',
    #     'gtmeec': r'(_gtmeec)',
    #     'topics_api': r'(topicsLastReferenceTime|ayads-browsingTopics)',
    #     'engagement_metrics': r'(eng_mt|poool-engage)',
    #     'page_tracking': r'(os_pageViews|pagesHistory|pagesVisited|\\bnbp\\b|pageLoadTimestamp)',
    #     'adobe_tracking': r'(com\\.adobe\\.reactor\\.core\\.visitorTracking)',
    #     'popup_tracking': r'(BetterJsPop_lastOpenedAt)',
    #     'session_state': r'(_shs_state)',
    #     'ar_timestamps': r'(arTimestamps|arLastUrl)',
    #     'onesignal_pageview': r'(onesignal-pageview-count)',
    #     'intervals': r'(rIntervals)',
    #     'adobe_visitor_tracking': r'(com\.adobe\.reactor\.core\.visitorTracking)',
    #     'marfeel_extended': r'(marfeel-sdk-store)',
    #     'page_amount': r'(lexpress_pagesAmount|pagesAmount)',
    #     'visited_flag': r'(\bvisited\b)',
    #     'surveillance': r'(idSurveillanceCurrentPage)',
    #     'klaviyo_count': r'(klaviyoPagesVisitCountV2)',
    #     'page_index': r'(page_index|pageIndex)',
    #     'latest_ts': r'(latest_ts|latest_fn)',
    #     'browsing_history_extended': r'(browsingHistory)',
    #     'cache_dict': r'(trc_cache_dict)',
    #     'app_insights': r'(AI_sentBuffer|AI_buffer)',
    #     'elapsed_time': r'(_cyb_elapsedTime)',
    #     'page_count_extended': r'(akcelo_page_count|boxzilla_pageviews)',
    #     'session_pageviews': r'(omSessionPageviews)',

    # },

'BEHAVIORAL_DATA': {
        'mouse_tracking': r'(mouse_pos|cursor_x|cursor_y|mouse_move|pointer_events|hover_data)',
        'click_tracking': r'(click_map|click_count|last_clicked|interaction_log|tap_targets|current_click)',
        'scroll_tracking': r'(scroll_depth|scroll_pos|max_scroll|page_height|fold_height|\bscroll\b)',
        'timing_metrics': r'(dwell_time|time_on_page|session_duration|timestamp_start|interaction_time|active_time|LastActivityTimestamp|timetoclick)',
        'input_logging': r'(keystroke|input_tracking|form_analytics|field_focus|typing_speed)',
        # Session Replay Vendors
        'vendor_session_replay': r'(_hjSession|_hjUserId|_clck|_clsk|CLID|fs_uid|fs_interim|_ceg|_ces|logrocket|^lr_|mf_user|mf_session)',
        'tab_focus': r'(window_focus|blur_time|focus_time|visibility_change)',
        'viewport_tracking': r'(innerWidth|innerHeight|devicePixelRatio|screenWidth|screenHeight)',
        'touch_tracking': r'(touch_start|touch_end|touch_move|gesture)',
        # Google/YouTube Usage
        'usage_telemetry': r'(latencyAction|visualElement|tickName|clientActionNonce|serializedEventId|eventTimeMs|lastActivityMs|latencyActionTicked|idbTransactionEnded|objectStoreNames)',
        'interaction_tracking': r'(_interaction|_interaction_resume|_highengaged_iteminteractions|_highengaged_filterinteractions|_parsely_slot_click)',
        'engagement_metrics': r'(eng_mt|poool-engage|onesignal-pageview-count|klaviyoPagesVisitCountV2|boxzilla_pageviews|omSessionPageviews)',
        'topics_api': r'(topicsLastReferenceTime|ayads-browsingTopics)',
        'popup_tracking': r'(BetterJsPop_lastOpenedAt)',
        'surveillance': r'(idSurveillanceCurrentPage)',
        'page_nav_events':r'(PageViewEvent)',
        'timestamp_key': r'\b(timestamp|created_at|updated_at|last_visit|event_time|session_start|creationTime|expiresIn|lastSentHeartbeatDate|lastHeartbeatDate|lastHeartbeatTimestamp|lastHeartbeatTimestamp|LastUsed)\b',
    },


    # IDENTITY_TRACKING: vendor-AGNOSTIC identifier mechanisms only.
    # Anything naming a specific company/product lives in ID_SOLUTIONS_AND_EXCHANGES instead
    # (or in SESSION_MANAGEMENT / FINGERPRINTING_ADVANCED when it's a framework/mechanism
    # that already has its own dedicated category).
    'IDENTITY_TRACKING': {
        'generic_ids': r'(visitor_id|device_id|client_id|browser_id|uuid|guid|[_-]uid[_-]?|^uid$|session_id|user_hash|visitorId|sessionid|PVID|VID)',
        'generic_adtech': r'(idsync|uuid|[_-]sid[_-]?|^sid$)',
        'first_party_ids': r'(FPID|FPID2|FPGSID|ope_fpid|FPAU|FPLC)',
        'tracking_ids': r'(trackerId|tracking_id|cid|\buid\b|userId|clientId|\buids\b)',
        'hash_ids': r'(\bhash\b|hashSessionId|redhash)',
        'cluster_session': r'(\bcluster\b|\bsp\b)',
        'auth_key': r'(authKey|authToken|refreshToken|accessToken)',
        'geoip_enabled': r'(geoIP)',
        'algorithm_id': r'(algorithm_parameters.id)',
        'persistence_vectors': r'(evercookie|ec_cache|fp_cache|device_hash|fingerprint_id|machine_id)',
    },

    'APP_STATE_STORAGE': {
        'redux_state': r'^(persist:|redux|root_state)',
        'vue_state': r'^(vuex|pinia|app_state)',
        'firebase_auth': r'(firebase:authUser|firebase:installations)',
        'apollo_cache': r'(apollo-cache|graphql_cache)',
        'cart_data': r'(cart_items|basket_data|shopping_cart)',
        'ngrx_state': r'^(ngrx|store_state)',
        'pwa_indexeddb': r'(idb_.*|indexeddb_cache)',
        'magento': r'(mage-messages|mage-cache-storage|mage-banners-cache-storage)',
        'ecommerce_history': r'(recently_compared_product|recently_viewed_product)',
        'shopify_session': r'(_shopify_s)',
       
        'session_state': r'(wzsession|session22)',
        'product_storage': r'(product_data_storage)',
        'device_view': r'(device_view|localization)',
        'elementor': r'(elementor)',
        'i18next': r'(i18nextLng)',
        'local_storage_version': r'(__lsv__|__wpfvdk)',
        'oct8ne': r'(oct8neApi-)',
        'feature_flags': r'(feh--[a-z0-9]+)',
        
        'mage_cache_timeout': r'(mage-cache-timeout)',
        'search_form': r'(searchform)',
        'oct8ne_extended': r'(oct8ne-active-tab-id|oct8ne-checkdomain-result)',
        'feature_flags_opts': r'(opt_out|opt-out|optout)',
        'app_state': r'(lastconfig|settings|config)',
    },

    
    'SUSPICIOUS_VALUES': {
        'url_list': r'(https?%3A%2F%2F|https?://).*(?:,|\||%7C).*(https?%3A%2F%2F|https?://)',
        'base64_json': r'^ey[A-Za-z0-9+/]{20,}={0,2}$',
        'php_serialized': r'^(a:\d+:\{|O:\d+:|s:\d+:)',
        'uuid_format': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        'geo_coordinates': r'("?lat"?\s*[:=]\s*[-+]?\d+\.\d+|"?long"?\s*[:=]\s*[-+]?\d+\.\d+)',
        'jwt_token': r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$',
        'auth_tokens': r'(session_token|auth_token|csid|[_-]sid[_-]?|^sid$|\bjwt\b|^jwt$|jwtToken|authToken)',
        'auth0_patterns': r'(auth0|auth0_compat|bkng_sso_auth)',
        'api_keys': r'(_key|api_key|form_key|pd_key|co_key|apiKey|api_key)',
        'google_rollout': r'(__Secure-ROLLOUT_TOKEN)',
        'tracking_extended': r'(__ktpct)',
    },

    'DEVICE_ENV': {
        'os_browser': r'(userAgent|platform|navigator_os|navigator_browser)',
        'screen_resolution': r'(screenWidth|screenHeight|devicePixelRatio|\bresolution\b)',
        'language': r'(navigator_language|lang|locale)',
        'youtube_device': r'(X-YouTube-Device|X-YouTube-Page-Label)',
        'youtube_visitor': r'(VISITOR_PRIVACY_METADATA|VISITOR_INFO1_LIVE|YSC)',
        'device_memory': r'(deviceMemory|hardware_concurrency)',
        'time_zone': r'(timezone|timeZoneOffset|Intl_DateTimeFormat)',
        'plugins_mime': r'(navigator_plugins|mimeTypes|plugin_data)',
        'touch_support': r'(maxTouchPoints|ontouchstart|touchEvent)',
        'browser_info':r'(browserName|browserVersion|osName|connectionType|hl|gl|clientName|clientVersion|X-YouTube-Utc-Offset|X-YouTube-Time-Zone)',
        'posthog': r'(ph_phc_[A-Za-z0-9]+_posthog)',
        'device_detection': r'(\bkhaos\b|khaos_p)',

        'user_agent_extended': r'(userAgent|browser|platform)',
        'screen_extended': r'(screen|viewport|resolution)',
    },

    'FINGERPRINTING_ADVANCED': {
        'webgl_canvas': r'(webgl_vendor|webgl_renderer|unmasked_vendor|unmasked_renderer|gl_extensions|canvas_winding|canvas_todataurl)',
        'audio_context': r'(audio_fingerprint|oscillator_node|dynamics_compressor|audio_context_id)',
        'hardware_concurrency': r'(hardware_concurrency|device_memory|cpu_class|platform_ua)',
        'battery_network': r'(battery_level|charging_time|connection_rtt|downlink_max)',
        'fonts_installed': r'(font_list|available_fonts|font_hash|text_metrics)',
        'user_agent_data': r'(user-agent-data)',
        # moved from IDENTITY_TRACKING - generic (non-vendor) fingerprint signals
        'generic_fingerprint_keys': r'(fingerprint|canvas_hash|device_fingerprint|fpjs|browser_signature)',
        'generic_fingerprint_audio_webgl': r'(fp_audio|fp_webgl|canvas_fp)',
        'vendor_salesforce_expansion': r'(_KMPage|_KnowledgePageDispatcher|_KnowledgePageFilter|_KnowledgePageFilterArticleArticleType|_KnowledgePageFilterArticlePublishStatus|_KnowledgePageFilterArticleValidationStatus|_KnowledgePageFilterLanguage|_KnowledgePageFilterMyDraftArticleType|_KnowledgePageFilterMyDraftPublishStatus|_KnowledgePageFilterMyDraftValidationStatus|_KnowledgePageSortFieldArticle|_KnowledgePageSortFieldMyDraft|_spring_KmMlAnyoneDraftArticlesList|_spring_KmMlArchivedArticlesList|_spring_KmMlMyDraftArticlesList)',
        'vendor_awin_expansion': r'(lantern|AwinChannelCookie)',
        'vendor_baidu_expansion': r'(Hm_lpvt_|Hm_lvt_|HMACCOUNT)',
        'vendor_cheq_expansion': r'(_cq_duid|_cq_suid)',
        'vendor_leadinfo_expansion': r'(_li_id|_li_ses)',
        'vendor_mercadolibre_expansion': r'(_d2id|edsid|ftid)',
        'vendor_microsoft_expansion': r'(_clck|_clsk|SM|CLID|MicrosoftApplicationsTelemetryDeviceId|esctx\-|isFirstSession|MSO|X\-FD\-FEATURES|X\-FD\-Time|ASP\.NET_Sessio|ASP\.NET_Sessio_Fallback|\.AspNetCore\.Antiforgery\.|__RequestVerificationToken)',
        'vendor_oracle_expansion': r'(JSESSIO|ORA_WWV_APP_|ELOQUA|ELQSTATUS)',
        'vendor_stripe_expansion': r'(__stripe_mid|__stripe_sid|m)',
        'vendor_tapad_expansion': r'(TapAd_DID|TapAd_TS|TapAd_3WAY_SYNCS)',
        'vendor_teads_expansion': r'(tt_viewer|tt_bluekai|tt_exelate|tt_liveramp|tt_neustar|tt_salesforce)',
        'vendor_yandex_expansion': r'(_ym_metrika_enabled|_ym_isad|_ym_uid|_ym_d|yabs\-sid|_ym_debug|_ym_visorc_|_ym_hostIndex|yandexuid|yuidss|ymex|usst|is_gdpr_b|is_gdpr|yabs\-vdrf)',
        'vendor_itch_expansion': r'(tuuid_lu|api_token|unique_id|unique_id_durable|session_unique_id|server_session_id|twitch\.lohp\.countryCode|auth\-token|enable\-compact\-scene\-listing|videoChat\.notice_dismissed|chat_rules_shown|algoliasearch\-client\-js|device_id|referrer_url|sentry_device_id)',
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
        'ccpa_gpp': r'(us_privacy|gpp_string|gpp_sid|usprivacy)',
        'google_consent': r'(^gcs$|^gcd$|consented_purposes|google.*consent|FCNEC|FCCDCF)',
        'trust_commander': r'(TC_PRIVACY|TC_PRIVACY_CENTER|TCPID)',
        'didomi': r'(didomi_token|didomi_cookies|didomi_dcs|didomi_but)',
        'cmp_generic': r'(consent_FID|v_acceptCookies|cookie_policy|has_consented|CMPRO|trustarc|cookieyes|usercentrics|consensu|quantcast|cmp_v2|privacy_manager)',
        'consent_management': r'(consent|CONSENTMGR)',
        'optanon': r'(Optanon|OneTrust|OptanonConsent)',
        'cookie_notice': r'(cookie.*notice|cookie.*alert|cookie.*banner|CookieAlert|DC-Cookie)',
        'gdpr_patterns': r'(\bgdpr\b|gdpr_cookie|gdpr_opt|gdpr_pd|rgpd_cookies)',
        'complianz': r'(cmplz_functional|cmplz_statistics|cmplz_marketing|cmplz_banner|cmplz_policy_id)',
        'piwik_pro': r'(ppms_privacy_[a-f0-9\-]+)',
        'cookie_deprecation': r'(receive-cookie-deprecation|COOKIE_SUPPORT)',
        'axeptio': r'(axeptio_authorized_vendors|axeptio_cookies|axeptio_all_vendors)',
        'tarteaucitron': r'(tarteaucitron)',
        'sddan_cmp': r'(sddan:cmp)',
        'cmp_validation': r'(eqtv_cmpvalid)',
        'permission_state': r'(_wpinitialpermissionstate)',
        'dnt': r'(ayads-dnt)',
        'is_eu': r'(is_eu)'
    },

        
        
    'SERVER_SIDE_TRACKING': {
        'facebook_capi': r'(fbp_em|fbp_ph|external_id|client_user_agent|fbc_id)',
        'google_enhanced': r'(enhanced_conversions|user_data_hash|sha256_email)',
        'facebook_ssl': r'(fbssls_[0-9]+)',
    },


 
     'USER_PREFERENCES': {
        'theme': r'(dark_mode|light_mode|theme_preference)',
        'language': r'(lang_preference|locale|preferred_language|fr-FR)',
        'notifications': r'(notification_pref|email_notifications|push_notifications)',
        'privacy': r'(tracking_opt_out|cookie_consent|ad_personalization)',
        'layout': r'(dashboard_layout|view_mode|grid_preference)',
        'other_settings': r'(font_size|timezone|currency)',
        'ab_testing_state': r'(optimizely|vwo_|ab_test|split_group|experiment_id|variant_id|bucket_id|_vis_opt)',
        'user_config_storage': r'(user_data|user_config|site_settings|app_config|visitor_config|sub19|sub20|settings_blob)',
        'preference_endpoints': r'(preferences?_url|preferences?_host|pref_endpoint|sync_preferences)',
        
        'abtasty': r'(ABTasty|abtasty)',
    },


'UX_AND_PERFORMANCE_ANALYTICS': {
    'contentsquare': r'(_cs_id|_cs_s|_cs_c|_cs_cvars|_cs_ex|_cs_mk|_cs_root)',
    'chartbeat': r'(_chartbeat|_cb_svref|_cb_ls)',
    'datadog': r'(_dd_s|_dd_r|dd_site)',
    'appdynamics': r'(ADRUM|ADRUM_BT)',
    'hotjar_clarity': r'(_hjSession|_hjUserId|_clck|_clsk)',
    'ab_testing_generic': r'(ab\.storage|ab_test|ab_group|_abck|AB_|obs_ab|ezoab_|experiment_|ABTest_)',
    'ab_testing_doctolib': r'(acid_practitioner_visibility|acid_smart_ranking|acid_marketing|acid_booking|acid_search)',
    'tealium': r'(utag_main|utag_)',
    'piano_analytics': r'(pa_user|pa_privacy|pa_vid)',
    'atinternet': r'(atid|atuserid)',
    'adobe_analytics': r'(s_cc|s_plt|s_ppv|s_ips|s_pltp|s_tslv|s_sq|s_vi|s_fid)',
    'adobe_marketing_cloud': r'(AMCV_[A-F0-9]+%40AdobeOrg|AMCVS_[A-F0-9]+%40AdobeOrg)',
    'adobe_kndctr': r'(kndctr_[A-F0-9]+_AdobeOrg_identity|kndctr_[A-F0-9]+_AdobeOrg_cluster)',
    'performance_testing': r'(3pc_test|DotomiTest|\bTEST\b|test-actifs|chkChromeAb)',
    'debug_mode': r'(ar_debug)',
    'audit_tracking': r'(\baudit\b|audit_p)',
        'abt_datalayer': r'(ABT_IS_DATALAYER_CHECKED|ABT_DATALAYER_INTERVAL_ID|ABT_ENOUGH_TIME_ELAPSED)',
        'campaign_source': r'(cgSource|cgSourceDomain)',
        'vr_injector': r'(VR-INJECTOR-INSTANCES-MAP)',
    'metrics_tracking': r'(mst_[A-Za-z0-9]+)',
    'vendor_zoho_expansion': r'(zc_consent|ZCAMPAIGN_CSRF_TOKEN|zc_show|zc_cu_exp|zc_loc|uesign)',
    'vendor_dynatrace_expansion': r'(dtCookie|dtLatC|dtPC|dtSa|dtValidationCookie|dtDisabled|rxVisitor|rxvt|b925d32c|ssoCSRFCookie|p23mn32t|l34kn6no|iu2g34bw|a69k21bb|cgq80xhu)',
    'vendor_blueconic_expansion': r'(BCSessionID|BCTempID|BCPermissionLevel|BCReferrerOverrule|BCRefusedObjectives|BCRevision|BCTracking|bc_tstgrp)',
    'vendor_contentsquare_expansion': r'(_cs_c|_cs_cvars|_cs_id|_cs_s|__CT_Data|_CT_RS_|WRUID|_cs_ex|_cs_optout|_cs_rl|_cs_root\-domain|WRIgnore|WRBlock|_cs_same_site|_cs_debug)',
    'vendor_crazy_egg_expansion': r'(_ceir|_CEFT|_cer\.v|_ce\.s|_ce\.cch|_ce\.gtld|ce_need_secure_cookie|ce_successful_csp_check|cebs|cebsp_|_ce\.clock_event|_ce\.clock_data|_ce\.irv|ceft_variant_override|_crazyegg)',
    'vendor_inspectlet_expansion': r'(__insp_pad|__insp_sid|__insp_ref|__insp_scpt|__insp_nv|__insp_wid|__insp_uid|__insp_dct|__insp_norec_sess|__insp_slim|__insp_targlpt|__insp_targlpu)',
    'vendor_plausible_expansion': r'(plausible_)',
    'vendor_siteimprove_expansion': r'(nmstat)',
    'vendor_shopify_p2_expansion': r'(_tracking_consent|_landing_page|_orig_referrer|_s|_shopify_fs|_shopify_sa_t|_shopify_uniq|_shopify_visit|_shopify_y|_y|tracked_start_checkout|ki_r|ki_t|_Brochure_session|_shopify_d|shop_analytics|_shopify_sa_p|_shopify_ga)',
    'vendor_yandex_metrica_p2_expansion': r'(_ym_metrika_enabled|_ym_isad|_ym_uid|_ym_d|yabs\-sid|_ym_visorc_|yandexuid|yuidss|ymex|usst|is_gdpr_b|is_gdpr|yabs\-vdrf|bh|_yasc|yashr)',
    'vendor_qualtrics_p2_expansion': r'(QSI_HistorySession|QSI_OptInIDsAndWindowNames|QSI_OptInIDsAndTargetOrigins|SiteReferrer|PageReferrer|SearchTerm|FocusTime|BlurTime|ActionSetHistory|SISessID|CPSessID|QSI_ReplaySession_Info_|QSI_TestSessions_|QSI_SI_)',
    'vendor_piwik_p2_expansion': r'(stg_traffic_source_priority|stg_last_interaction|stg_returning_visitor|stg_externalReferrer|_pk_id\.|_pk_ses\.|ppms_privacy_bar_|stg_fired__|stg_utm_campaign|stg_pk_campaign|_stg_optout|stg_global_opt_out)',
    'vendor_matomo_p2_expansion': r'(_pk_id|_pk_ref|_pk_ses|_pk_cvar|_pk_hsr|_pk_testcookie|mtm_consent|mtm_consent_removed|mtm_cookie_consent|matomo_ignore|matomo_sessid)',
    'vendor_hotjar_p2_expansion': r'(_hjHasCachedUserAttributes|_hjid|hj_visitor|_hjIncludedInSample|_hjClosedSurveyInvites|_hjDonePolls|_hjMinimizedPolls|_hjDoneTestersWidgets|_hjMinimizedTestersWidgets|_hjShownFeedbackMessage|_hjCachedUserAttributes)',
    'vendor_piano_p2_expansion': r'(_pcus|cX_P|cX_G|gckp|pnespsdk_visitor|pnespsdk_push_subscription_added|pnespsdk_pnespid|__pvi|__pat)',
    'vendor_google_analytics_p2_expansion': r'(_gali|_dc_gtm_|AMP_TOKEN|_gat_gtag_|__utmc|__utmv|__utmx|__utmxx)',
    'vendor_marketo_p2_expansion': r'(_biz_uid|_biz_nA|_biz_flagsA|_biz_pendingA|_biz_ABTestA|_biz_su|_biz_EventA)',
    'vendor_dynamic_yield_p2_expansion': r'(_dy_csc_ses|_dycmc|_dy_df_geo|_dy_geo|_dycst|_dy_cs_storage_items|_dy_cs_cookie_items)',
    'vendor_amplitude_p2_expansion': r'(AMP_MKTG_|AMP_TEST|AMP_TLDTEST|amplitude_cookie_test|amplitude_id_|amplitude_test)',
    'vendor_wordpress_p2_expansion': r'(tk_qs|tk_lr|tk_or|tk_r3d|tk_tc|camptix_client_stats)',
    'vendor_woocommerce_p2_expansion': r'(sbjs_udata|sbjs_first|sbjs_current|sbjs_first_add|sbjs_current_add|sbjs_migrations)',
    'vendor_google_optimize_p2_expansion': r'(_opt_awkid|_opt_awgid|_opt_awmid|_gaexp_rc|_opt_awcid|_opt_expid)',
    'vendor_tripadvisor_p2_expansion': r'(TADCID|ServerPool|TATravelInfo|TAUnique|TAReturnTo)',
    'vendor_cognitoforms_p2_expansion': r'(c\-referrer|c\-signup|c\-plan|cognito\.services\.a|cognito\.organization)',
    'vendor_indeed_p2_expansion': r'(CTK|ctkgen|INDEED_CSRF_TOKEN|jasx_pool_id|pagead/conv/%INTEGER%)',
    'vendor_kentico_p2_expansion': r'(CMSCsrfCookie|CMSLandingPageLoaded|CMSUserPage|CurrentContact|VisitorStatus)',
    'vendor_lucky_orange_p2_expansion': r'(_lo_uid|_lo_rid|_lo_v|__lotl|__lotr)',
    'vendor_duda_p2_expansion': r'(dm_timezone_offset|dm_last_visit|dm_total_visits|dm_last_page_view|dm_this_page_view)',
    'vendor_taboola_p2_expansion': r'(taboola_session_id|_tb_t_ppg|abLdr|abMbl|tb_click_param)',
    'vendor_xandr_p2_expansion': r'(usersync|pses|uids|XANDR_PANID)',
    'vendor_picreel_p2_expansion': r'(picreel_tracker__visited|picreel_tracker__first_visit|picreel_tracker__page_views|picreel_new_price)',
    'vendor_ablyft_p2_expansion': r'(ablyft_exps|ablyft_queue|ablyft_uvs|ablyft_tracking_consent)',
    'vendor_beslist_nl_p2_expansion': r'(client_bslstaid|client_bslstmatch|client_bslstsid|client_bslstuid)',
    'vendor_bazaar_voice_p2_expansion': r'(BVBRANDID|BVBRANDSID|BVID|BVSID)',
    'vendor_sharethis_p2_expansion': r'(__stid|__stidv|pxcelBcnLcy|pxcelPage)',
    'vendor_adobe_analytics_p2_expansion': r'(fid|s_ecid|s_tp)',
    'vendor_wikimedia_p2_expansion': r'(WMF\-Last\-Access|centralnotice_bucket|NetWorkProbeLimit)',
    'vendor_mailchimp_p2_expansion': r'(mc_cid|mc_eid|mc_landing_site)',
    'vendor_visual_website_optimizer_p2_expansion': r'(_vwo_sn|_vwo_ds|_vwo_referrer)',
    'vendor_snowplow_p2_expansion': r'(sp|_sp_id\.|_sp_ses\.)',
    'vendor_vimeo_p2_expansion': r'(vuid|sd_identity|sd_client_id)',
    'vendor_intercom_p2_expansion': r'(intercom\-id\-|intercom\-session\-|intercom\-device\-id\-)',
    'vendor_heap_analytics_p2_expansion': r'(_hp2_id|_hp2_ses_props)',
    'vendor_ahoy_p2_expansion': r'(ahoy_visit|ahoy_visitor)',
    'vendor_oribi_p2_expansion': r'(oribi_user_guid|oribi_cookie_test)',
    'vendor_sleeknote_p2_expansion': r'(_sn_a|_sn_m)',
    'vendor_mopinion_com_p2_expansion': r'(Pastease\.passive\.activated|Pastease\.passive\.chance)',
    'vendor_wepublish_p2_expansion': r'(_wepublishGa|_wepublishGa_gid)',
    'vendor_zendesk_p2_expansion': r'(_zdshared_user_session_analytics|ZD\-buid)',
    'vendor_comscore_p2_expansion': r'(S1|C1)',
},
'SECURITY_AND_BOT_MITIGATION': {
    'cloudflare': r'(__cf_bm|_cfuvid|cf_clearance|cf_ob_info|cf_use_ob)',
    'recaptcha_google': r'(_GRECAPTCHA|_grecaptcha)',
    'anti_csrf': r'(__RequestVerificationToken|csrf_token|xsrf-token|_csrf)',
    'imperva_incapsula': r'(incap_ses|visid_incap|nlbi_)',
    'datadome': r'(datadome)',
    'akamai_bot': r'(_abck|bm_sz|bm_sv|ak_bmsc)',
    'auth_security': r'(auth_token|secure_session|login_csrf)',
    'oauth': r'(oauth|OAuth)',
    'dtm_token': r'(dtm_token)',
    'vendor_paypal_expansion': r'(enforce_policy|x\-pp\-s|ts|ts_c|tsrce|nsid|X\-PP\-SILOVER|X\-PP\-L7|l7_az)',
    'vendor_cleantalk_expansion': r'(apbct_antibot|ct_check_js|ct_fkp_timestamp|ct_has_scrolled|ct_pointer_data|ct_ps_timestamp|ct_timezone|apbct_cookies_test|apbct_|ct_|ct_sfw_|spbc_cookies_test|spbc_firewall_pass_key|spbc_is_logged_in|spbc_2fa_passed)',
    'vendor_github_p2_expansion': r'(gist_oauth_csrf|_octo|saml_csrf_token)',
    'vendor_auth0_p2_expansion': r'(a0_users:sess|a0_users:sess\.sig)',
},

'SESSION_MANAGEMENT': {
    'php_session': r'(PHPSESSID|SESS[0-9a-f]{26}|php_fw_[a-z_]+)',
    'java_session': r'(JSESSIONID)',
    'generic_session': r'(SESSID|cookiesession|session_id|SESSIONID|sessionToken)',
    'asp_session': r'(ASP\.NET_SessionId)',
    # widened to absorb the old IDENTITY_TRACKING 'aspnet_sessions' entry (was a near-duplicate)
    'aspnet_core': r'(\.AspNetCore\.[A-Za-z\.]+|\.ASPXAUTH)',
    'laravel': r'(laravel_session)',
    'nautilus': r'(nautisession_v3)',
    'generic_session_extended': r'(jhenligne|\bcsd\b|\bHMS\b|\bctx\b)',
    'keycloak': r'(KC_RESTART)',
    # moved from IDENTITY_TRACKING - framework/mechanism-level session patterns, not vendor names
    'rails_session': r'(_[a-z0-9_]+_session)',
    'session_private_key': r'(sessionPrivateKey)',
    'sso_generic': r'(SSO_[a-zA-Z0-9\.]+)',
},

'INFRASTRUCTURE': {
    'load_balancer': r'(AWSELB|AWSALB|SERVERID|server_id|lb_id)',
    'cdn_routing': r'(akamai|cloudflare|fastly|cdn_|edge_)',
    'f5_bigip': r'(BIGipServer|TS[a-f0-9]{8})',
    'cache_session': r'(cache_session|session_cache)',
    'sequence_counter': r'\b(sequenceNumber|sequence_id|seq_num)\b',

    
    # IndexedDB Architecture (generic metadata keys)
    'idb_meta_version': r'\.version$',
    'idb_meta_offset': r'\.offset$',
    'idb_meta_type': r'\.type$',
    'idb_meta_value': r'\.value$',
    'idb_meta_entries': r'\.entries\[\d+\]',
    'indexeddb_metadata': r'(registrationStatus|dataCollectionEnabled|localeOverride|subscriptionDomain)',
    'idb_structure_key':r'(__type__|ObjectStoreDataValue|IDBKeyPath|blob_size|blob_offset|database_id|blob_number|BlobJournalEntry)',
},

# 'CUSTOMER_INTERACTION': {
#     'chat_support': r'(iadvize|intercom|zendesk|livechat|crisp|drift)',
#     'marketing_overlays': r'(wisepops|batch|beamer|hellobar)',
#     'feedback_tools': r'(usabilla|qualtrics|medallia)',
#     'silverpop': r'(com\.silverpop\.iMA\.(page_visit|session))',
#     'linkedin_extended': r'(li_sugr)',
# },


'DIRECT_PII_KEYS': {
    # Email
    'email_key': r'\b(email|mail|e-mail|e_mail|userEmail|user_email|emailAddress|email_address|correo|courriel)\b',
    
    # Phone
    'phone_key': r'\b(phone|tel|telephone|mobile|cellphone|phoneNumber|phone_number|telefono|tel_number)\b',
    
    # Name
    'first_name_key': r'\b(firstName|first_name|prenom|givenName|given_name|forename|customer_firstname)\b',
    'last_name_key': r'\b(lastName|last_name|nom|surname|familyName|family_name|customer_lastname)\b',
    'full_name_key': r'\b(fullName|full_name|displayName|display_name|username|user_name|userName)\b',
    
    # Address
    'address_key': r'\b(address|street|streetAddress|street_address|adresse|rue)\b',
    'city_key': r'\b(city|ville|town|locality)\b',
    'postal_code_key': r'\b(zipCode|zip_code|postalCode|postal_code|postcode|cp|codePostal)\b',
    'country_key': r'\b(country|pays|nation)\b',
    
    # Birth date
    'birthdate_key': r'\b(birthDate|birth_date|birthDay|birth_day|dob|dateOfBirth|date_of_birth|birthday|dateNaissance|date_naissance)\b',
    'birth_year_key': r'\b(birthYear|birth_year|yearOfBirth|year_of_birth|anneeNaissance)\b',
    'birth_month_key': r'\b(birthMonth|birth_month|monthOfBirth|month_of_birth|moisNaissance)\b',
    'birth_day_key': r'\b(birthDay|birth_day|dayOfBirth|day_of_birth|jourNaissance)\b',
    
    # User ID
    'user_id_key': r'\b(userId|user_id|customerId|customer_id|accountId|account_id|memberId|member_id|clientId|client_id)\b',

    # Password (intention de stocker - TRÈS sensible)
    'password_key': r'\b(password|passwd|pwd|pass|userPassword|user_password|motDePasse|mot_de_passe)\b',
    
    # Gender
    'gender_key': r'\b(gender|sex|sexe|genre|civilite)\b',
    
    # Payment info
    'credit_card_key': r'\b(creditCard|credit_card|cardNumber|card_number|cardNum|carte|numeroCarte)\b',
    'cvv_key': r'\b(cvv|cvc|securityCode|security_code|cryptogramme)\b',
    
    # SSN / National ID
    'ssn_key': r'\b(ssn|social_security|socialSecurity|social_security_number|numeroSecu|secu)\b',
    'national_id_key': r'\b(nationalId|national_id|taxId|tax_id|nin|nif|cni)\b',
    
    # Age
    'age_key': r'\b(age|userAge|user_age|\bAge\b)\b',
    'timestamp_key': r'\b(timestamp|created_at|updated_at|last_visit|event_time|session_start)\b',
    
    # Geolocation (IndexedDB)
    'geolocation': r'\b(latitude|longitude|geoLocation|country_code|region|city|postal_code|area_code|continent_code)\b',
    'location_data': r'\b(location|position|coordinates|geo)\b',
    
}
}