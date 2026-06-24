#!/bin/bash
# Z-SIEM PostgreSQL initialization
# Creates the n8n database alongside the iris database

set -e

echo "[Z-SIEM] Creating n8n database..."
psv -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE n8n;
    CREATE USER n8n WITH PASSWORD '${N8N_DB_PASSWORD:-n8ndemo2026}';
    GRANT ALL PRIVILEGES ON DATABASE n8n TO n8n;
EOSQL

echo "[Z-SIEM] Granting n8n user on iris database (for cross-schema queries if needed)..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "n8n" <<-EOSQL
    GRANT ALL ON SCHEMA public TO n8n;
    ALTER DATABASE n8n OWNER TO n8n;
EOSQL

echo "[Z-SIEM] Done. Databases: iris, n8n"
