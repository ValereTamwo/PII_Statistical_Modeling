#!/usr/bin/env python3
"""
Script principal pour exécuter tous les scripts de prétraitement
"""

import subprocess
import sys
from pathlib import Path


def run_script(script_name):
    """Exécute un script Python"""
    script_path = Path(__file__).parent / script_name
    
    print(f"\n{'='*60}")
    print(f"Exécution de {script_name}")
    print(f"{'='*60}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            check=True,
            capture_output=False
        )
        print(f"\n✓ {script_name} terminé avec succès")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Erreur lors de l'exécution de {script_name}")
        print(f"Code de retour: {e.returncode}")
        return False


def main():
    """Exécute tous les scripts de prétraitement"""
    print("\n" + "="*60)
    print("PRÉTRAITEMENT DES DONNÉES FR_0417")
    print("="*60)
    
    scripts = [
        'extract_cookies.py',
        'extract_localstorage.py',
        'extract_sessionstorage.py'
        'extract_indexeddb.py'
    ]
    
    results = {}
    
    for script in scripts:
        results[script] = run_script(script)
    
    # Résumé
    print("\n" + "="*60)
    print("RÉSUMÉ")
    print("="*60)
    
    for script, success in results.items():
        status = "✓ Succès" if success else "✗ Échec"
        print(f"{status:12} - {script}")
    
    all_success = all(results.values())
    
    if all_success:
        print("\n✓ Tous les scripts ont été exécutés avec succès!")
        print("\nLes fichiers CSV sont disponibles dans:")
        print("  - preprocessing/cookies/")
        print("  - preprocessing/localstorage/")
        print("  - preprocessing/sessionstorage/")
    else:
        print("\n✗ Certains scripts ont échoué. Vérifiez les erreurs ci-dessus.")
        sys.exit(1)


if __name__ == '__main__':
    main()
