#!/usr/bin/env bash
# Add exclusions to the existing cloud-init hotplug rule, preserving its
# physical NIC behavior. Does not trigger udev or restart network services.
set -euo pipefail
ROOT=${GOVPN_GUARD_ROOT:-}
RULE="$ROOT/etc/udev/rules.d/90-cloud-init-hook-hotplug.rules"
SOURCE=$RULE
if [ ! -f "$SOURCE" ]; then
  for d in /usr/lib/udev/rules.d /lib/udev/rules.d; do
    if [ -f "$ROOT$d/90-cloud-init-hook-hotplug.rules" ]; then
      SOURCE="$ROOT$d/90-cloud-init-hook-hotplug.rules"
      break
    fi
  done
fi
[ -f "$SOURCE" ] || exit 0
python3 - "$SOURCE" "$RULE" <<'PY'
import os,sys,tempfile
src,dst=sys.argv[1:]
text=open(src).read()
if '# GoVPN hotplug exclusions' in text:
    sys.exit(0)
# Scope only the exact known cloud-init RUN helper; unknown variants must
# be inspected instead of silently clearing other udev RUN commands.
lines=text.splitlines(keepends=True)
found=False
out=[]
for line in lines:
    if 'RUN+=' in line and '/usr/lib/cloud-init/hook-hotplug' in line and not line.lstrip().startswith('#'):
        found=True
        out.append('# GoVPN hotplug exclusions: virtual tunnels are not cloud NICs\n')
        line='KERNEL!="wg-s[0-9]*", KERNEL!="wg-c[0-9]*", KERNEL!="govpn", KERNEL!="wg-hub", '+line
    out.append(line)
if not found:
    raise SystemExit('Unknown cloud-init hotplug rule format; inspect before creating tunnels')
os.makedirs(os.path.dirname(dst),exist_ok=True)
if os.path.exists(dst):
    backup=dst+'.govpn-original'
    if not os.path.exists(backup):
        with open(backup,'x') as f: f.write(text)
        os.chmod(backup,0o600)
fd,tmp=tempfile.mkstemp(prefix='.govpn-',dir=os.path.dirname(dst))
try:
    with os.fdopen(fd,'w') as f: f.write(''.join(out))
    os.chmod(tmp,0o644)
    os.replace(tmp,dst)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
if [ -z "$ROOT" ]; then
  udevadm verify --no-style "$RULE"
  udevadm control --reload-rules
fi
