#!/bin/bash
# Script de migration FR_00XX → FR_04XX
# Usage: bash migration_ids.sh

set -e  # Arrêter en cas d'erreur

echo "=========================================="
echo "Migration FR_00XX → FR_04XX"
echo "=========================================="
echo ""

# Fonction de renommage sécurisée
rename_if_exists() {
  if [ -d "$1" ]; then
    echo "✓ Renommage: $1 → $2"
    mv "$1" "$2"
  else
    echo "⊘ Ignoré (n'existe pas): $1"
  fi
}

# Backup avant migration
echo "1. Création d'un backup..."
timestamp=$(date +%Y%m%d_%H%M%S)
backup_dir="backup_migration_$timestamp"
mkdir -p "$backup_dir"
echo "   Backup créé dans: $backup_dir"
echo ""

# Data directories
echo "2. Migration des dossiers data/..."
for auth in Auth UnAuth; do
  for base in preprocessing user raw; do
    rename_if_exists "data/$base/$auth/FR_0017" "data/$base/$auth/FR_0417"
    rename_if_exists "data/$base/$auth/FR_0018" "data/$base/$auth/FR_0418"
    rename_if_exists "data/$base/$auth/FR_0019" "data/$base/$auth/FR_0419"
  done
done
echo ""

# Results directory
echo "3. Migration des dossiers results/..."
for auth in Auth UnAuth; do
  rename_if_exists "results/$auth/FR_0017" "results/$auth/FR_0417"
  rename_if_exists "results/$auth/FR_0018" "results/$auth/FR_0418"
  rename_if_exists "results/$auth/FR_0019" "results/$auth/FR_0419"
done
echo ""

echo "=========================================="
echo "✓ Migration des dossiers terminée"
echo "=========================================="
echo ""
echo "PROCHAINES ÉTAPES:"
echo "1. Modifier les boucles dans les scripts:"
echo "   users = ('FR_0417', 'FR_0418', 'FR_0419')"
echo ""
echo "2. Corriger les emails dans user_profiles.json"
echo ""
echo "3. Compléter les patterns dans regex.py"
echo ""
echo "Voir: verification_finale.md pour les détails"
