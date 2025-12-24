import statsmodels.api as sm
from statsmodels.formula.api import ols
from statsmodels.stats.multicomp import pairwise_tukeyhsd
from statsmodels.stats.diagnostic import het_breuschpagan
from statsmodels.stats.stattools import durbin_watson
import pandas as pd
import numpy as np
from scipy import stats
from scipy.stats import shapiro, levene, kruskal, wilcoxon, ttest_rel

def calculate_cohens_d(x, y):
    """Calculate Cohen's d for effect size."""
    nx = len(x)
    ny = len(y)
    dof = nx + ny - 2
    return (np.mean(x) - np.mean(y)) / np.sqrt(((nx-1)*np.std(x, ddof=1) ** 2 + (ny-1)*np.std(y, ddof=1) ** 2) / dof)

def calculate_eta_squared(anova_table):
    """Calculate Eta-squared from ANOVA table."""
    ss_effect = anova_table['sum_sq'][:-1].sum()
    ss_total = anova_table['sum_sq'].sum()
    return ss_effect / ss_total if ss_total > 0 else 0

def calculate_omega_squared(anova_table):
    """Calculate Omega-squared (less biased than eta-squared)."""
    results = {}
    ms_error = anova_table.loc['Residual', 'sum_sq'] / anova_table.loc['Residual', 'df']
    ss_total = anova_table['sum_sq'].sum()
    
    for idx in anova_table.index[:-1]:  # Exclude Residual
        ss_effect = anova_table.loc[idx, 'sum_sq']
        df_effect = anova_table.loc[idx, 'df']
        omega_sq = (ss_effect - df_effect * ms_error) / (ss_total + ms_error)
        results[idx] = max(0, omega_sq)  # Omega-squared can be negative, floor at 0
    
    return results

def calculate_icc(df, dependent_var):
    """Calculate Intraclass Correlation Coefficient."""
    # Group by user and calculate between/within variance
    user_means = df.groupby('user')[dependent_var].mean()
    grand_mean = df[dependent_var].mean()
    
    # Between-group variance
    n_per_group = df.groupby('user').size().mean()
    between_var = np.sum((user_means - grand_mean)**2) / (len(user_means) - 1)
    
    # Within-group variance
    within_var = df.groupby('user')[dependent_var].var().mean()
    
    # ICC calculation
    icc = between_var / (between_var + within_var) if (between_var + within_var) > 0 else 0
    return icc

def calculate_reduction_rates(df, dependent_var):
    """Calculate reduction rates between policies."""
    policy_means = df.groupby('policy')[dependent_var].mean()
    
    rates = {}
    if 'ALL' in policy_means.index and 'PARTIAL' in policy_means.index:
        rates['ALL_to_PARTIAL'] = ((policy_means['ALL'] - policy_means['PARTIAL']) / policy_means['ALL'] * 100) if policy_means['ALL'] > 0 else 0
    
    if 'ALL' in policy_means.index and 'NONE' in policy_means.index:
        rates['ALL_to_NONE'] = ((policy_means['ALL'] - policy_means['NONE']) / policy_means['ALL'] * 100) if policy_means['ALL'] > 0 else 0
    
    if 'PARTIAL' in policy_means.index and 'NONE' in policy_means.index:
        rates['PARTIAL_to_NONE'] = ((policy_means['PARTIAL'] - policy_means['NONE']) / policy_means['PARTIAL'] * 100) if policy_means['PARTIAL'] > 0 else 0
    
    return rates

def jonckheere_terpstra_test(df, dependent_var):
    """Test for monotonic trend across ordered groups (ALL > PARTIAL > NONE)."""
    # Manual implementation of Jonckheere-Terpstra
    groups = ['ALL', 'PARTIAL', 'NONE']
    data_groups = [df[df['policy'] == g][dependent_var].values for g in groups if g in df['policy'].unique()]
    
    if len(data_groups) < 2:
        return None, None
    
    # Calculate J statistic
    J = 0
    for i in range(len(data_groups)):
        for j in range(i+1, len(data_groups)):
            for x in data_groups[i]:
                for y in data_groups[j]:
                    if x > y:
                        J += 1
    
    # Expected value and variance (simplified)
    n = sum(len(g) for g in data_groups)
    E_J = n * (n - 1) / 4
    
    # Z-score approximation
    var_J = n * (n - 1) * (2 * n + 5) / 72
    z_score = (J - E_J) / np.sqrt(var_J) if var_J > 0 else 0
    p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))
    
    return z_score, p_value

def test_assumptions(df, dependent_var, model):
    """Test ANOVA assumptions: Normality, Homoscedasticity, Independence."""
    results = {}
    
    # 1. Normality (Shapiro-Wilk on residuals)
    residuals = model.resid
    if len(residuals) >= 3:
        shapiro_stat, shapiro_p = shapiro(residuals)
        results['shapiro_wilk'] = {'statistic': shapiro_stat, 'p_value': shapiro_p}
    
    # 2. Homoscedasticity (Levene's test)
    groups = [group[dependent_var].values for name, group in df.groupby(['storage', 'auth', 'policy'])]
    groups = [g for g in groups if len(g) > 0]
    if len(groups) >= 2:
        levene_stat, levene_p = levene(*groups)
        results['levene'] = {'statistic': levene_stat, 'p_value': levene_p}
    
    # 3. Independence (Durbin-Watson)
    dw_stat = durbin_watson(residuals)
    results['durbin_watson'] = {'statistic': dw_stat}
    
    return results

def bootstrap_ci(data, stat_func, n_bootstrap=1000, ci=95):
    """Calculate bootstrap confidence interval for a statistic."""
    bootstrap_stats = []
    n = len(data)
    
    for _ in range(n_bootstrap):
        sample = np.random.choice(data, size=n, replace=True)
        bootstrap_stats.append(stat_func(sample))
    
    lower = np.percentile(bootstrap_stats, (100 - ci) / 2)
    upper = np.percentile(bootstrap_stats, 100 - (100 - ci) / 2)
    
    return lower, upper

def permutation_test(group1, group2, n_permutations=1000):
    """Perform permutation test for difference in means."""
    observed_diff = np.mean(group1) - np.mean(group2)
    combined = np.concatenate([group1, group2])
    n1 = len(group1)
    
    perm_diffs = []
    for _ in range(n_permutations):
        np.random.shuffle(combined)
        perm_diff = np.mean(combined[:n1]) - np.mean(combined[n1:])
        perm_diffs.append(perm_diff)
    
    p_value = np.mean(np.abs(perm_diffs) >= np.abs(observed_diff))
    return observed_diff, p_value

def run_comprehensive_analysis(df, dependent_var='exposure_score'):
    """
    Run the complete suite of statistical tests as per the modeling document.
    """
    print(f"\n{'='*70}")
    print(f"COMPREHENSIVE STATISTICAL ANALYSIS: {dependent_var}")
    print(f"{'='*70}")
    
    # ========================================================================
    # PHASE 1: DESCRIPTIVE STATISTICS
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 1: DESCRIPTIVE STATISTICS")
    print("="*70)
    
    print("\n--- Summary Statistics by Group ---")
    summary = df.groupby(['storage', 'auth', 'policy'])[dependent_var].agg(['count', 'mean', 'std', 'min', 'max'])
    print(summary)
    
    print("\n--- Marginal Means ---")
    print("By Storage:")
    print(df.groupby('storage')[dependent_var].agg(['mean', 'std']))
    print("\nBy Auth:")
    print(df.groupby('auth')[dependent_var].agg(['mean', 'std']))
    print("\nBy Policy:")
    print(df.groupby('policy')[dependent_var].agg(['mean', 'std']))
    
    # ========================================================================
    # PHASE 2: MAIN EFFECTS & INTERACTIONS (ANOVA)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 2: ANOVA FACTORIELLE (H1, H2, H3, H5)")
    print("="*70)
    
    try:
        formula = f'{dependent_var} ~ C(storage) + C(auth) + C(policy) + C(storage):C(auth) + C(storage):C(policy) + C(auth):C(policy)'
        model = ols(formula, data=df).fit()
        anova_table = sm.stats.anova_lm(model, typ=2)
        
        print("\n--- ANOVA Table ---")
        print(anova_table)
        
        # Effect sizes
        eta_sq = calculate_eta_squared(anova_table)
        omega_sq = calculate_omega_squared(anova_table)
        
        print(f"\n--- Effect Sizes ---")
        print(f"Global Eta-squared (η²): {eta_sq:.4f}")
        print("\nOmega-squared (ω²) by factor:")
        for factor, value in omega_sq.items():
            print(f"  {factor}: {value:.4f}")
        
        # Test assumptions
        print("\n--- Assumption Tests ---")
        assumptions = test_assumptions(df, dependent_var, model)
        if 'shapiro_wilk' in assumptions:
            print(f"Shapiro-Wilk (Normality): W={assumptions['shapiro_wilk']['statistic']:.4f}, p={assumptions['shapiro_wilk']['p_value']:.4f}")
        if 'levene' in assumptions:
            print(f"Levene (Homoscedasticity): F={assumptions['levene']['statistic']:.4f}, p={assumptions['levene']['p_value']:.4f}")
        if 'durbin_watson' in assumptions:
            print(f"Durbin-Watson (Independence): {assumptions['durbin_watson']['statistic']:.4f} (ideal: ~2.0)")
        
    except Exception as e:
        print(f"Error in ANOVA: {e}")
        model = None
    
    # ========================================================================
    # PHASE 3: POST-HOC TESTS
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 3: POST-HOC COMPARISONS (H1)")
    print("="*70)
    
    # Tukey HSD for Policy
    print("\n--- Tukey HSD (Policy) ---")
    try:
        tukey = pairwise_tukeyhsd(endog=df[dependent_var], groups=df['policy'], alpha=0.05)
        print(tukey)
    except Exception as e:
        print(f"Error in Tukey HSD: {e}")
    
    # Jonckheere-Terpstra trend test
    print("\n--- Jonckheere-Terpstra Trend Test (ALL > PARTIAL > NONE) ---")
    try:
        jt_z, jt_p = jonckheere_terpstra_test(df, dependent_var)
        if jt_z is not None:
            print(f"Z-score: {jt_z:.4f}, p-value: {jt_p:.4f}")
            if jt_p < 0.05:
                print("✓ Significant monotonic trend detected")
            else:
                print("✗ No significant monotonic trend")
    except Exception as e:
        print(f"Error in Jonckheere-Terpstra: {e}")
    
    # Reduction rates
    print("\n--- Reduction Rates Between Policies ---")
    try:
        rates = calculate_reduction_rates(df, dependent_var)
        for comparison, rate in rates.items():
            print(f"{comparison}: {rate:.2f}%")
    except Exception as e:
        print(f"Error calculating reduction rates: {e}")
    
    # ========================================================================
    # PHASE 4: EFFECT SIZES (H2)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 4: EFFECT SIZES (H2 - Auth vs UnAuth)")
    print("="*70)
    
    try:
        auth_group = df[df['auth'] == 'Auth'][dependent_var].dropna()
        unauth_group = df[df['auth'] == 'UnAuth'][dependent_var].dropna()
        
        if len(auth_group) > 0 and len(unauth_group) > 0:
            d_val = calculate_cohens_d(auth_group, unauth_group)
            print(f"\nCohen's d (Auth vs UnAuth): {d_val:.4f}")
            
            # Interpretation
            if abs(d_val) >= 0.8:
                print("  → Large effect")
            elif abs(d_val) >= 0.5:
                print("  → Medium effect")
            elif abs(d_val) >= 0.2:
                print("  → Small effect")
            else:
                print("  → Negligible effect")
            
            # Paired t-test
            print("\n--- Paired t-test (Auth vs UnAuth) ---")
            # Reshape for pairing
            auth_vals = df[df['auth'] == 'Auth'].sort_values(['storage', 'policy', 'user'])[dependent_var].values
            unauth_vals = df[df['auth'] == 'UnAuth'].sort_values(['storage', 'policy', 'user'])[dependent_var].values
            
            if len(auth_vals) == len(unauth_vals):
                t_stat, t_p = ttest_rel(auth_vals, unauth_vals)
                print(f"t-statistic: {t_stat:.4f}, p-value: {t_p:.4f}")
                
                # Wilcoxon (non-parametric alternative)
                print("\n--- Wilcoxon Signed-Rank Test (Auth vs UnAuth) ---")
                w_stat, w_p = wilcoxon(auth_vals, unauth_vals)
                print(f"W-statistic: {w_stat:.4f}, p-value: {w_p:.4f}")
            
            # Permutation test
            print("\n--- Permutation Test (Auth vs UnAuth) ---")
            perm_diff, perm_p = permutation_test(auth_group.values, unauth_group.values, n_permutations=1000)
            print(f"Observed difference: {perm_diff:.4f}, p-value: {perm_p:.4f}")
            
    except Exception as e:
        print(f"Error in effect size calculations: {e}")
    
    # ========================================================================
    # PHASE 5: ROBUSTNESS (H4)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 5: ROBUSTNESS ANALYSIS (H4 - Inter-user Variability)")
    print("="*70)
    
    try:
        # Coefficient of Variation
        print("\n--- Coefficient of Variation (CV) per User ---")
        user_stats = df.groupby('user')[dependent_var].agg(['mean', 'std'])
        user_stats['cv'] = (user_stats['std'] / user_stats['mean']) * 100
        print(user_stats)
        
        mean_cv = user_stats['cv'].mean()
        print(f"\nMean CV across users: {mean_cv:.2f}%")
        if mean_cv < 30:
            print("✓ Good robustness (CV < 30%)")
        elif mean_cv < 50:
            print("⚠ Acceptable robustness (30% ≤ CV < 50%)")
        else:
            print("✗ High variability (CV ≥ 50%)")
        
        # ICC
        print("\n--- Intraclass Correlation Coefficient (ICC) ---")
        icc = calculate_icc(df, dependent_var)
        print(f"ICC: {icc:.4f}")
        if icc >= 0.75:
            print("  → Strong similarity within users")
        elif icc >= 0.5:
            print("  → Moderate similarity within users")
        else:
            print("  → Weak similarity within users")
        
        # Bootstrap CI for mean
        print("\n--- Bootstrap 95% CI for Grand Mean ---")
        all_data = df[dependent_var].dropna().values
        if len(all_data) > 0:
            lower, upper = bootstrap_ci(all_data, np.mean, n_bootstrap=1000, ci=95)
            print(f"Mean: {np.mean(all_data):.2f}, 95% CI: [{lower:.2f}, {upper:.2f}]")
        
    except Exception as e:
        print(f"Error in robustness analysis: {e}")
    
    # ========================================================================
    # PHASE 6: STORAGE COMPARISON (H5)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 6: STORAGE TYPE COMPARISON (H5)")
    print("="*70)
    
    try:
        # Kruskal-Wallis (non-parametric alternative to one-way ANOVA)
        print("\n--- Kruskal-Wallis Test (Storage Types) ---")
        storage_groups = [group[dependent_var].values for name, group in df.groupby('storage')]
        h_stat, kw_p = kruskal(*storage_groups)
        print(f"H-statistic: {h_stat:.4f}, p-value: {kw_p:.4f}")
        
        if kw_p < 0.05:
            print("✓ Significant differences between storage types")
        else:
            print("✗ No significant differences between storage types")
        
    except Exception as e:
        print(f"Error in storage comparison: {e}")
    
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70 + "\n")
    
    return model
