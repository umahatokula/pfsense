# Super Admin Recovery Account – Storage & Filesystem Prep

## Objectives
- Persist recovery-account metadata outside `config.xml`.
- Ensure metadata survives config restores/imports and basic tampering.
- Provide controlled write flow: default read-only, explicit remount for updates.
- Lay groundwork for integrity monitoring and immutable flags.

## Proposed Layout
```
/conf
  ├── config.xml
  └── recovery_admin/
        ├── metadata.json        # username, external auth pointer, token identifiers
        ├── credentials.hash     # optional encrypted secret (if required)
        └── version              # schema version for migrations
```

Example `metadata.json` (version `1`)

```json
{
  "username": "recovery-admin",
  "auth_backend": "radius-recovery",
  "token_type": "yubikey",
  "token_attribute": "Reply-Message",
  "token_identifier": "ccccccdefghijklnopqrstuvabcd",
  "console_access": true,
  "created_at": "2025-03-10T12:34:00Z",
  "notes": "Emergency recovery account, maintain token in secure storage."
}
```

- `recovery_admin` directory owned by `root:wheel`, mode `0700`.
- Metadata stored as JSON to simplify parsing outside PHP if necessary.
- Apply `chflags schg` to directory and files after writes; provide helper to remove/set during updates.
- Maintain accompanying checksum file (e.g., SHA-256) for monitoring.

## Helper Scripts
1. **`/etc/rc.recovery_admin_mount`**  
   - Called early in boot to ensure `/conf` is mounted read-only, then reapply immutable flags.  
   - Validates directory structure; recreates with correct permissions when missing.

2. **`/usr/local/sbin/recovery_admin_update`**  
   - CLI utility that:
     - Temporarily removes `schg` flag.
     - Remounts `/conf` as read-write (using `mount -u -o rw /conf`).
     - Applies updates passed via stdin or file.
     - Regenerates checksum.
     - Restores `schg` and remounts `/conf` read-only.
   - Ensures GUI/CLI code uses the same safe path for updates.

3. **`/usr/local/sbin/recovery_admin_check`**
   - Scheduled task to verify metadata checksums, permissions, and alert on anomalies.
   - Emits syslog warnings on drift and returns non-zero for external monitoring.

4. **`/usr/local/sbin/system_integrity_check`**
   - Generates and verifies SHA-256 baselines for core authentication/recovery files.
   - `--init` rewrites `/conf/recovery_admin/core_files.sha256`; boot runs `--check` and logs differences.

## Integration Points
- GUI/API flows call `recovery_admin_update` through sudoers rule instead of writing files directly.
- Dedicated management UI at `System > User Management > Recovery Admin` exposes metadata editing via the helper.
- Login enforcement checks an auth-server attribute (`token_attribute`) against the stored hardware token identifier.
- Backup/restore utilities skip this directory (handled separately) but provide hooks to warn if missing.
- HA sync excludes `recovery_admin` directory from XMLRPC, with dedicated secure copy later.

## Next Steps
1. Implement shell helpers with unit tests / dry-run mode.
2. Update PHP wrappers (`auth.inc` or new service class) to leverage helpers.
3. Add integrity check skeleton (checksum generation + verification).
4. Document operational procedures for administrators.
