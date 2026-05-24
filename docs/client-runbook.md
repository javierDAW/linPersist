# linpersist — client deployment runbook

> Bilingual (EN / ES). The English section is authoritative for
> the kit; the Spanish translation is provided for operator
> convenience.
>
> **Audience**: the IT / SecOps team of a client engagement, who
> will deploy `linpersist` across their fleet and return the
> resulting NDJSON to the consultoría operator.

---

## EN — How to run linpersist

### 0. What you received

The consultoría operator handed you a tarball named like:

```
linpersist-v0.5.0-engagement-kit.tar.gz
```

Inside (`tar tzf <kit>` to inspect):

```
linpersist-vX.Y.Z-engagement-kit/
  linpersist-linux-amd64           # the agent (run on every host)
  linpersist-linux-arm64           # ARM64 variant of the agent
  linpersist-report-linux-amd64    # analyst-side tool (run on operator laptop, NOT clients)
  linpersist-report-linux-arm64    # ARM64 variant
  RUNBOOK.md                       # this document
  SCOPE.md                         # what the agent does/does not do
  LICENSE
  README.md
  CHANGELOG.md
  sample-report.html               # example of the analyst output you will receive
  sample-report.txt                # text version of the same
  CHECKSUMS.txt                    # sha256 of every file in the kit
```

### 1. Verify the kit before deploying anything

The kit's integrity check is `CHECKSUMS.txt`. From inside the extracted directory:

```bash
sha256sum -c CHECKSUMS.txt
# Expected: every line ends with "OK"
```

If any line says `FAILED`, **do not deploy** — contact the operator
to re-send.

For higher assurance, the GitHub Release publishes `.sig` and `.pem`
files for each binary, signed with cosign keyless via GitHub OIDC.
Verify a binary independently with:

```bash
cosign verify-blob \
  --certificate linpersist-linux-amd64.pem \
  --signature   linpersist-linux-amd64.sig \
  --certificate-identity-regexp 'https://github.com/.+/linPersist/.+' \
  --certificate-oidc-issuer    'https://token.actions.githubusercontent.com' \
  linpersist-linux-amd64
# Expected: "Verified OK"
```

The verifier needs no shared secret. The signature is bound to the
GitHub Actions workflow run that produced it, via the Fulcio
certificate chain.

At runtime, the agent will report its own sha256 if asked. Use this
on each target host immediately before the collection run to
confirm the binary on disk is the one you handed over:

```bash
./linpersist-linux-amd64 --self-sha256
# Output: <sha256>  /full/path/to/linpersist-linux-amd64
```

This SHA must match the entry in `CHECKSUMS.txt`.

### 2. What the agent does (one paragraph)

The agent walks a fixed set of Linux persistence sites (cron,
systemd, /etc/passwd, ssh authorized_keys, etc. — full list in
`SCOPE.md`) and emits one JSON record per artifact to **stdout**.
It does NOT make network calls, install services, modify
inspected files, or read SSH/TLS private keys. The complete list
of things it never does is enumerated in `SCOPE.md` section 2.

### 3. What you need to do

1. Deploy the `linpersist-linux-amd64` (or `-arm64`) binary to every
   host in scope.
2. Run it as root (recommended) or as a user with
   `CAP_DAC_READ_SEARCH` — see SCOPE.md §5.
3. Redirect stdout to a per-host file named after the hostname.
4. Collect all those files into a single directory.
5. Deliver the directory (or a tarball of it) back to the operator
   via the agreed channel (encrypted email, sFTP, etc.).

The operator will run `linpersist-report` against the collected
directory on their own laptop and deliver an HTML/PDF analysis.

### 4. Recommended invocation

```bash
sudo ./linpersist \
  --include-hostname \
  --tag engagement=ACME-2026-05-24 \
  --tag role=$(facter role 2>/dev/null || echo unknown) \
  > /tmp/linpersist-$(hostname).ndjson
```

Flags explained:

| Flag | Why |
|---|---|
| `--include-hostname` | Emits the plaintext hostname (default is hash only). Helpful for the operator to correlate hosts to your inventory |
| `--tag KEY=VALUE` | Repeatable. Lands in `host_meta.tags[]`. The operator uses these for peer-group analysis (e.g. `role=db-replica` clusters database hosts together) |
| `>` redirect | Stdout is NDJSON. Capture it; do not let it scroll past |

Common tag schemes (pick what fits your inventory):
`role={web,db,build-ci,k8s-node,bastion,...}`,
`env={prod,staging,dev}`,
`datacenter={us-east-1,eu-west-2,...}`.

### 5. Deployment patterns

Pick the pattern that matches your existing infrastructure.

#### Ansible

```yaml
# linpersist-collect.yml
- hosts: all
  become: yes
  vars:
    engagement_id: ACME-2026-05-24
    kit_url: https://internal-bastion/kit/linpersist-linux-amd64
    expected_sha: 3601700822d63d922c04d9d7407d3010b6adc4df60be6697d6d989f059611422
  tasks:
    - name: Stage agent binary
      get_url:
        url: "{{ kit_url }}"
        dest: /usr/local/bin/linpersist
        mode: '0755'
        checksum: "sha256:{{ expected_sha }}"
    - name: Run collection
      shell: |
        /usr/local/bin/linpersist \
          --include-hostname \
          --tag engagement={{ engagement_id }} \
          --tag role={{ ansible_role | default('unknown') }} \
          > /tmp/linpersist-{{ inventory_hostname }}.ndjson
      args:
        executable: /bin/bash
    - name: Fetch NDJSON
      fetch:
        src: /tmp/linpersist-{{ inventory_hostname }}.ndjson
        dest: ./collected/
        flat: yes
    - name: Wipe binary
      file:
        path: /usr/local/bin/linpersist
        state: absent
```

Run with `ansible-playbook -i inventory linpersist-collect.yml`,
then deliver `./collected/` to the operator.

#### AWS SSM Run Command

```bash
# Stage binary in S3 once (or use a private bucket pre-set in your kit)
aws s3 cp linpersist-linux-amd64 s3://my-bucket/kits/linpersist

aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets "Key=tag:env,Values=prod" \
  --parameters 'commands=[
    "set -eu",
    "aws s3 cp s3://my-bucket/kits/linpersist /tmp/linpersist",
    "echo \"3601700822...  /tmp/linpersist\" | sha256sum -c -",
    "chmod +x /tmp/linpersist",
    "/tmp/linpersist --include-hostname --tag engagement=ACME-2026-05-24 > /tmp/linp.ndjson",
    "aws s3 cp /tmp/linp.ndjson s3://my-bucket/engagements/ACME-2026-05-24/$(hostname).ndjson",
    "rm -f /tmp/linpersist /tmp/linp.ndjson"
  ]' \
  --max-concurrency 50 \
  --max-errors 5
```

After all targets complete, sync `s3://my-bucket/engagements/ACME-2026-05-24/`
to a local directory and deliver to the operator.

#### systemd timer (for proactive monthly hunt)

```ini
# /etc/systemd/system/linpersist-hunt.service
[Unit]
Description=Monthly linpersist persistence hunt

[Service]
Type=oneshot
ExecStart=/usr/local/bin/linpersist \
  --include-hostname \
  --tag engagement=monthly-hunt \
  --tag role=%H \
  --output /var/log/linpersist/%H-%i.ndjson
```

```ini
# /etc/systemd/system/linpersist-hunt.timer
[Unit]
Description=Monthly linpersist persistence hunt

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now linpersist-hunt.timer
# Outputs land in /var/log/linpersist/*.ndjson; ship to operator monthly
```

#### Manual single-host (test or one-off)

```bash
sudo /usr/local/bin/linpersist --include-hostname > host.ndjson
```

That's it. Done.

### 6. After the collection — what happens next

1. You deliver `engagement-<id>/` (a directory of `*.ndjson` files,
   one per host) to the operator.
2. The operator runs `linpersist-report -i engagement-<id>/ -o report.html`
   on their laptop. The report renders fleet-wide LFA, MITRE
   coverage, implant roll-call, etc.
3. The operator briefs you on findings.

You can also self-render the report on your side (the operator
gives you the same tool):

```bash
./linpersist-report-linux-amd64 \
  -i engagement-ACME-2026-05-24/ \
  -o engagement-ACME-2026-05-24.html
```

Both HTML and text formats are supported (`--format html|text`).

### 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `linpersist: open /etc/shadow: permission denied` | Not running as root | Re-run with `sudo` or grant `CAP_DAC_READ_SEARCH` |
| `dpkg: command not found` warnings in stderr | Provenance lookup; harmless on hosts without dpkg | Add `--no-provenance` to silence |
| Output file 0 bytes | stderr was redirected, not stdout. Use `> file`, not `2> file` | Verify your shell redirect |
| Records have `errors[]` populated | Specific files were unreadable; the rest of the record is still emitted | Inspect the field; usually a perms issue on a specific path |
| Agent hangs on `/usr/bin` | Provenance scan on a host with millions of dpkg entries | Add `--provenance-timeout 30s` or `--no-provenance` |
| `cosign verify-blob` says `Verified` but the operator's cert pattern is unfamiliar | The kit was rebuilt from a fork or branch | Confirm the operator's repo identity matches the regexp in §1 |

### 8. Securely deleting the kit after the engagement

When the engagement is concluded:

```bash
# Wipe the binary from every target host (Ansible example)
ansible all -m file -a "path=/usr/local/bin/linpersist state=absent" --become

# Shred the kit on your operator coordination host
shred -uvz linpersist-*-engagement-kit.tar.gz
shred -uvz collected/*.ndjson

# Optional: rotate any S3/object-store paths used to stage the kit
```

The agent has no persistent installation; removing the binary
removes the agent entirely. There is no daemon, no service, no
hook to clean up.

---

## ES — Cómo ejecutar linpersist

### 0. Qué has recibido

El operador de consultoría te ha entregado un tarball con nombre tipo:

```
linpersist-v0.5.0-engagement-kit.tar.gz
```

Dentro contiene los dos binarios (agente + herramienta de análisis), este
runbook, el documento de scope (`SCOPE.md`), licencia, ejemplos de reporte y
un manifiesto SHA256 de todo el contenido.

### 1. Verifica la integridad del kit antes de desplegar

Desde el directorio extraído:

```bash
sha256sum -c CHECKSUMS.txt
# Esperado: cada línea termina en "OK"
```

Si alguna línea dice `FAILED`, **no despliegues** — contacta al operador
para reenvío.

Para garantía adicional, los binarios en la GitHub Release están firmados
con cosign keyless vía GitHub OIDC. Verifica con:

```bash
cosign verify-blob \
  --certificate linpersist-linux-amd64.pem \
  --signature   linpersist-linux-amd64.sig \
  --certificate-identity-regexp 'https://github.com/.+/linPersist/.+' \
  --certificate-oidc-issuer    'https://token.actions.githubusercontent.com' \
  linpersist-linux-amd64
# Esperado: "Verified OK"
```

En cada host justo antes de la ejecución, verifica el SHA256 del binario
que se va a ejecutar:

```bash
./linpersist-linux-amd64 --self-sha256
# Output: <sha256>  /ruta/completa/al/binario
```

Debe coincidir con la entrada de `CHECKSUMS.txt`.

### 2. Qué hace el agente (un párrafo)

Recorre un conjunto fijo de rutas Linux de persistencia (cron, systemd,
/etc/passwd, ssh authorized_keys, etc. — lista completa en `SCOPE.md`) y
emite un registro JSON por artefacto a **stdout**. NO hace llamadas de
red, NO instala servicios, NO modifica archivos inspeccionados, NO lee
claves privadas SSH/TLS. La lista completa de cosas que nunca hace está
en `SCOPE.md` sección 2.

### 3. Qué tienes que hacer

1. Distribuye `linpersist-linux-amd64` (o `-arm64`) a cada host en scope.
2. Ejecútalo como root (recomendado) o con `CAP_DAC_READ_SEARCH`.
3. Redirige stdout a un archivo por host con el hostname.
4. Recoge todos esos archivos en un solo directorio.
5. Entrega el directorio al operador por el canal acordado (email cifrado, sFTP, etc.).

### 4. Invocación recomendada

```bash
sudo ./linpersist \
  --include-hostname \
  --tag engagement=ACME-2026-05-24 \
  --tag role=$(facter role 2>/dev/null || echo unknown) \
  > /tmp/linpersist-$(hostname).ndjson
```

| Flag | Por qué |
|---|---|
| `--include-hostname` | Incluye el hostname en plaintext (default es solo hash). Útil para correlación con tu inventario |
| `--tag CLAVE=VALOR` | Repetible. Aterriza en `host_meta.tags[]`. El operador lo usa para análisis por peer-group (ej. `role=db-replica` agrupa todas las DBs) |
| `>` redirect | Stdout es NDJSON. Captúralo |

### 5. Patrones de despliegue

Los ejemplos de Ansible, AWS SSM, systemd timer y manual están en la
sección EN §5 — son shell/yaml, comprensibles sin traducción. Adapta
las URLs internas, S3 buckets y el `engagement-id` a tu entorno.

### 6. Después de la colección

1. Entregas `engagement-<id>/` al operador.
2. El operador genera el reporte con `linpersist-report` y te lo
   entrega.
3. Te explica los hallazgos.

También puedes renderizar el reporte por tu cuenta con la misma
herramienta:

```bash
./linpersist-report-linux-amd64 -i engagement-<id>/ -o report.html
```

### 7. Solución de problemas

Ver tabla en sección EN §7 — los síntomas y soluciones aplican igual.

### 8. Limpieza segura al cerrar el engagement

```bash
# Borra el binario de cada host (ejemplo Ansible)
ansible all -m file -a "path=/usr/local/bin/linpersist state=absent" --become

# Shred del kit en tu host de coordinación
shred -uvz linpersist-*-engagement-kit.tar.gz
shred -uvz collected/*.ndjson
```

El agente no tiene instalación persistente — eliminar el binario lo
elimina completamente. No hay daemon, ni servicio, ni hook que
limpiar.
