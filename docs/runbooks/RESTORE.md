# Sentinel Fabric V2 — Disaster Recovery Restore Runbook

> **Audience:** Platform SRE / On-Call Ops  
> **Last Updated:** 2026-03-27

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| `psql` / `pg_restore` | 15+ | PostgreSQL restore |
| `clickhouse-client` | 24.3+ | ClickHouse restore |
| `aws` CLI | 2.x | S3 artifact retrieval |
| `kubectl` | 1.28+ | Cluster access |
| `helm` | 3.x | Chart rollback |

Ensure `KUBECONFIG` points to the target cluster and you have `admin` RBAC.

---

## 1. Identify the Backup Artifact

Backups are written by the `db-backup` CronJob to the S3 bucket configured in `values.yaml` (`backups.s3Bucket`).

```bash
# List recent PostgreSQL backups
aws s3 ls s3://$S3_BUCKET/postgres/ --recursive | sort -r | head -10

# List recent ClickHouse backups
aws s3 ls s3://$S3_BUCKET/clickhouse/ --recursive | sort -r | head -10
```

Pick the most recent healthy artifact **before** the incident timestamp.

---

## 2. PostgreSQL Restore

### 2a. Scale down the backend to prevent writes

```bash
kubectl scale deployment sentinel-fabric-backend --replicas=0 -n sentinel
```

### 2b. Download and decompress the dump

```bash
aws s3 cp s3://$S3_BUCKET/postgres/pg_backup_YYYYMMDD_HHMMSS.sql.gz /tmp/
gunzip /tmp/pg_backup_YYYYMMDD_HHMMSS.sql.gz
```

### 2c. Restore into the database

```bash
# Option A: Full replacement (destructive — drops existing objects)
psql "postgresql://$DB_USER:$DB_PASS@$DB_HOST:5432/$DB_NAME" \
  -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" \
  -f /tmp/pg_backup_YYYYMMDD_HHMMSS.sql

# Option B: Side-load into a staging DB, then swap
createdb -h $DB_HOST -U $DB_USER sentinel_restore
psql "postgresql://$DB_USER:$DB_PASS@$DB_HOST:5432/sentinel_restore" \
  -f /tmp/pg_backup_YYYYMMDD_HHMMSS.sql
# Manually verify data, then rename databases via psql.
```

### 2d. Scale backend back up

```bash
kubectl scale deployment sentinel-fabric-backend --replicas=3 -n sentinel
```

### 2e. Validate

```bash
psql "postgresql://$DB_USER:$DB_PASS@$DB_HOST:5432/$DB_NAME" \
  -c "SELECT 'users' AS tbl, count(*) FROM users
      UNION ALL SELECT 'registered_assets', count(*) FROM registered_assets
      UNION ALL SELECT 'soar_audit_trail', count(*) FROM soar_audit_trail;"
```

---

## 3. ClickHouse Restore

### 3a. Restore from S3 backup

```bash
clickhouse-client --host $CH_HOST --query \
  "RESTORE DATABASE default FROM S3(
    'https://$S3_BUCKET.s3.amazonaws.com/clickhouse/backup_YYYYMMDD_HHMMSS/',
    '$AWS_ACCESS_KEY_ID',
    '$AWS_SECRET_ACCESS_KEY'
  );"
```

### 3b. Validate event counts

```bash
clickhouse-client --host $CH_HOST --query \
  "SELECT count() AS total_events, min(timestamp), max(timestamp) FROM events;"
```

---

## 4. Redis Cache Warm-Up

Redis is ephemeral and **not** backed up. After restore:

```bash
kubectl rollout restart deployment/sentinel-fabric-backend -n sentinel
```

Caches (asset criticality, sessions, campaigns) re-hydrate lazily from PostgreSQL/ClickHouse on first access.

---

## 5. Post-Restore Checklist

- [ ] `/api/v1/health` returns `200` on all pods
- [ ] Posture score recalculating (`GET /api/v1/posture/score`)
- [ ] Kafka consumer lag decreasing
- [ ] Test login confirms JWT issuance and session blocklist integrity
- [ ] Stakeholders notified via incident channel

---

## 6. Helm Rollback (Emergency)

```bash
helm history sentinel-fabric -n sentinel
helm rollback sentinel-fabric <REVISION> -n sentinel
```

---

## Emergency Contacts

| Role | Contact |
|------|---------|
| Platform SRE Lead | *Set in PagerDuty* |
| DBA On-Call | *Set in PagerDuty* |
| Security Ops | *Set in PagerDuty* |
