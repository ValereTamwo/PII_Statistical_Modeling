import pandas as pd
import numpy as np

def calculate_metrics(df):
    """
    Calculate derived metrics: Exposure Score, Modification Rate, Persistence Rate.
    """
    # Weights defined in the document
    w_critical = 4
    w_high = 3
    w_medium = 2
    w_low = 1
    
    # Exposure Score E(s,a,p,u)
    df['exposure_score'] = (
        df['critical_risk'] * w_critical +
        df['high_risk'] * w_high +
        df['medium_risk'] * w_medium +
        df['low_risk'] * w_low
    )
    
    # Lifecycle Metrics
    # T_mod = L_modified / L_added
    df['rate_modification'] = df.apply(lambda x: x['l_modified'] / x['l_added'] if x['l_added'] > 0 else 0, axis=1)
    
    # T_pers = (L_added - L_deleted) / L_added
    # Note: If l_deleted is missing (0), this assumes 100% persistence.
    # If l_deleted > l_added (which shouldn't happen logically but might in data), clip to 0.
    df['rate_persistence'] = df.apply(lambda x: (x['l_added'] - x['l_deleted']) / x['l_added'] if x['l_added'] > 0 else 0, axis=1)
    
    return df
