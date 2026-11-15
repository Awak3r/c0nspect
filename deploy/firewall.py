"""Narrow host firewall preflight and explicit opt-in web access (Linux, root).

The parent must call inspect_firewall before installing any host packages, then
call open_web_ports only for --open-web-ports. No provider firewall is managed.
Only the simple IPv4 filter INPUT baseline is supported outside active UFW.
"""

import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from operations import OperationError, run_command

RULES_V4 = Path('/etc/iptables/rules.v4')
UFW_FILES = (Path('/etc/ufw/user.rules'), Path('/etc/ufw/user6.rules'))
COMMENT = 'conspect-web-80-443'
WEB_RULE = (
    '-A', 'INPUT', '-p', 'tcp', '-m', 'multiport', '--dports', '80,443',
    '-m', 'conntrack', '--ctstate', 'NEW', '-m', 'comment', '--comment', COMMENT, '-j', 'ACCEPT',
)
REJECT = ('-A', 'INPUT', '-j', 'REJECT', '--reject-with', 'icmp-host-prohibited')
PATH_ERROR = 'Firewall paths must be absolute, root-owned, non-writable by group/others, and free of symlinks/hardlinks.'
LAYOUT_ERROR = (
    'Unsupported firewall layout; configure inbound TCP 80/443 and persistence manually, preserving SSH. '
    'Only an ACCEPT INPUT policy with the simple Oracle terminal REJECT baseline is supported.'
)
NFT_ERROR = (
    'Unsupported or inconsistent nftables layout; configure TCP 80/443 manually, preserving SSH. '
    'Only Docker-compatible FORWARD/NAT chains and the verified iptables-nft INPUT baseline are supported.'
)
DOCKER_CHAINS = {
    'DOCKER', 'DOCKER-USER', 'DOCKER-FORWARD', 'DOCKER-BRIDGE', 'DOCKER-CT',
    'DOCKER-INTERNAL', 'DOCKER-INGRESS', 'DOCKER-ISOLATION-STAGE-1', 'DOCKER-ISOLATION-STAGE-2',
}
PUBLIC_NOTE = (
    'If public access is still blocked, check provider security groups/security lists and any IPv6 firewall manually; '
    'provider rules are not configured here.'
)


def _command(arguments):
    try:
        return run_command(['env', 'LC_ALL=C', *arguments], stdin=subprocess.DEVNULL, timeout=30)
    except (OperationError, OSError, subprocess.SubprocessError, UnicodeError):
        raise OperationError(
            'Firewall command could not finish; inspect the firewall locally, then retry. '
            'Any completed narrow changes are retained; raw output withheld.'
        ) from None


def _directories(path):
    if not path.is_absolute() or '..' in path.parts:
        raise OperationError(PATH_ERROR)
    for directory in reversed((path, *path.parents)):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise OperationError(PATH_ERROR)


def _file(path):
    _directories(path.parent)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise OperationError(PATH_ERROR)
    return path.read_bytes()


def _host(root):
    if platform.system() != 'Linux' or getattr(os, 'geteuid', lambda: -1)() != 0:
        raise OperationError('Run firewall checks as root on the target Linux server.')
    root = Path(root)
    _directories(root)
    host = root / 'host'
    if os.path.lexists(host):
        _directories(host)
    return host


def _tokens(line):
    try:
        return tuple(shlex.split(line))
    except ValueError:
        raise OperationError(LAYOUT_ERROR) from None


def _baseline(rule):
    if rule in {('-A', 'INPUT', '-p', 'icmp', '-j', 'ACCEPT'),
                ('-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT')}:
        return True
    for module, flag in (('state', '--state'), ('conntrack', '--ctstate')):
        for states in ('RELATED,ESTABLISHED', 'ESTABLISHED,RELATED'):
            if rule == ('-A', 'INPUT', '-m', module, flag, states, '-j', 'ACCEPT'):
                return True
        for options in (('-m', module, flag, 'NEW', '-m', 'tcp', '--dport', '22'),
                        ('-m', 'tcp', '--dport', '22', '-m', module, flag, 'NEW')):
            if rule == ('-A', 'INPUT', '-p', 'tcp', *options, '-j', 'ACCEPT'):
                return True
    return False


def _layout(policy, rules):
    if policy != 'ACCEPT':
        raise OperationError(LAYOUT_ERROR)
    managed = [i for i, rule in enumerate(rules) if any(COMMENT in word for word in rule)]
    if managed and (len(managed) != 1 or rules[managed[0]] != WEB_RULE
                    or managed[0] != len(rules) - 2):
        raise OperationError('The managed firewall comment is duplicated, changed or misplaced; reconcile it manually.')
    if not managed and all(rule[:2] == ('-A', 'INPUT') and rule[-2:] == ('-j', 'ACCEPT') for rule in rules):
        return 'unrestricted'
    if not rules or rules[-1] != REJECT:
        raise OperationError(LAYOUT_ERROR)
    if any(rule != WEB_RULE and not _baseline(rule) for rule in rules[:-1]):
        raise OperationError(LAYOUT_ERROR)
    return 'managed' if managed else 'blocked'


def _runtime():
    lines = [_tokens(line) for line in _command(['iptables', '-w', '10', '-S', 'INPUT']).splitlines() if line.strip()]
    if not lines or lines[0] != ('-P', 'INPUT', 'ACCEPT'):
        raise OperationError(LAYOUT_ERROR)
    rules = lines[1:]
    return rules, _layout('ACCEPT', rules)


def _persistent(data):
    """Locate INPUT only; retain all other tables, chains, counters and bytes."""
    lines = data.decode('utf-8').splitlines(keepends=True)
    table = None
    seen = set()
    policy = None
    rules = []
    indices = []
    for index, line in enumerate(lines):
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        if text.startswith('*'):
            if table is not None or text in seen:
                raise OperationError(LAYOUT_ERROR)
            table = text
            seen.add(text)
        elif text == 'COMMIT':
            if table is None:
                raise OperationError(LAYOUT_ERROR)
            table = None
        elif table is None:
            raise OperationError(LAYOUT_ERROR)
        elif table == '*filter':
            if text.startswith(':INPUT '):
                if policy is not None or not re.fullmatch(r':INPUT ACCEPT \[\d+:\d+\]', text):
                    raise OperationError(LAYOUT_ERROR)
                policy = 'ACCEPT'
            elif text.startswith(':'):
                continue
            else:
                rule = _tokens(text)
                if len(rule) < 4 or rule[0] != '-A':
                    raise OperationError(LAYOUT_ERROR)
                if rule[1] == 'INPUT':
                    indices.append(index)
                    rules.append(rule)
    if table is not None or policy is None:
        raise OperationError(LAYOUT_ERROR)
    state = _layout(policy, rules)
    if state == 'unrestricted':
        raise OperationError('Persistent INPUT differs from the supported blocking baseline; reconcile rules.v4 manually.')
    if state == 'blocked':
        lines.insert(indices[-1], ' '.join(WEB_RULE) + '\n')
    return ''.join(lines).encode('utf-8'), state, rules


def _inspect(root):
    host = _host(root)
    # Do not use is-active: its normal nonzero "inactive" result is a command failure.
    if shutil.which('systemctl'):
        units = _command([
            'systemctl', 'list-units', '--all', '--state=active', '--type=service',
            '--no-legend', '--plain', '--no-pager', 'firewalld.service', 'nftables.service',
        ])
        if units.strip():
            raise OperationError('Active firewalld/nftables is unsupported; configure TCP 80/443 manually, preserving SSH.')
    elif shutil.which('firewall-cmd'):
        raise OperationError('Cannot verify firewalld is inactive; inspect it and configure web access manually.')
    if shutil.which('ufw'):
        status = _command(['ufw', 'status'])
        first = status.splitlines()[0] if status.splitlines() else ''
        if first == 'Status: active':
            files = [(path, _file(path)) for path in UFW_FILES]
            return host, 'ufw', files, status
        if first != 'Status: inactive':
            raise OperationError('Cannot identify UFW status; inspect UFW locally before retrying.')
    # An iptables-nft/native nft ruleset is deliberately outside the fallback.
    # Active UFW above is managed through UFW, never through its backend tables.
    if shutil.which('nft'):
        try:
            ruleset = json.loads(_command(['nft', '--json', 'list', 'ruleset']))
        except ValueError:
            raise OperationError('Cannot identify nftables rules; inspect the firewall manually.') from None
        if (not isinstance(ruleset, dict) or not isinstance(ruleset.get('nftables'), list)
                or any(not isinstance(item, dict) or set(item) != {'metainfo'}
                       for item in ruleset['nftables'])):
            raise OperationError('Nonempty or unknown nftables ruleset; configure TCP 80/443 manually, preserving SSH.')
    if not shutil.which('iptables'):
        return host, 'unknown', [], None
    rules, state = _runtime()
    if state == 'unrestricted':
        return host, state, [], rules
    if not shutil.which('netfilter-persistent'):
        raise OperationError('Existing netfilter-persistent is required; configure persistence manually. No packages will be installed.')
    data = _file(RULES_V4)
    updated, persistent_state, persisted_rules = _persistent(data)
    # Existing filter INPUT rules must agree; other tables are not ours to edit.
    if [rule for rule in rules if rule != WEB_RULE] != [rule for rule in persisted_rules if rule != WEB_RULE]:
        raise OperationError('Runtime and persistent INPUT baselines differ; reconcile them manually before opening ports.')
    return host, 'iptables', (data, updated, persistent_state), (rules, state)


def _report(kind):
    if kind == 'unknown':
        print('No host firewall is known: iptables is unavailable and no active supported firewall was found.')
    elif kind == 'unrestricted':
        print('No IPv4 INPUT firewall restriction; no changes necessary.')
    print(PUBLIC_NOTE)


def inspect_firewall(root) -> None:
    """Read-only pre-package preflight; does not imply consent to open ports."""
    try:
        _, kind, _, _ = _inspect(root)
        if kind in {'ufw', 'iptables'}:
            print('Supported host firewall found; opening TCP 80/443 requires explicit --open-web-ports opt-in.')
        _report(kind)
    except (OSError, UnicodeError):
        raise OperationError('Cannot safely inspect firewall files/paths; check root ownership, permissions and layout locally.') from None


def _backup(host, files):
    host.mkdir(mode=0o700, exist_ok=True)
    _directories(host)
    directory = Path(tempfile.mkdtemp(prefix='firewall-backup-', dir=host))
    for name, data in files:
        with (directory / name).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    _sync_directory(directory)
    _sync_directory(host)
    _sync_directory(host.parent)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def open_web_ports(root) -> None:
    """Explicit opt-in only. Retry safely after a partial runtime/persistence change."""
    temporary = None
    try:
        host, kind, files, runtime = _inspect(root)
        if kind == 'ufw':
            _backup(host, [(path.name, data) for path, data in files] + [('ufw-status.txt', runtime.encode('utf-8'))])
            for path, data in files:
                if _file(path) != data:
                    raise OperationError('UFW files changed during preflight; inspect locally and retry.')
            for port in ('80/tcp', '443/tcp'):
                _command(['ufw', 'allow', port])
        elif kind == 'iptables':
            original, updated, persistent_state = files
            rules, runtime_state = runtime
            if runtime_state == persistent_state == 'managed':
                _report(kind)
                return
            _backup(host, [('rules.v4', original), ('input.rules', ('\n'.join(shlex.join(rule) for rule in rules) + '\n').encode())])
            if persistent_state != 'managed':
                # Prepare and fsync the replacement before any runtime mutation.
                descriptor, temporary = tempfile.mkstemp(prefix='.conspect-firewall-', dir=RULES_V4.parent)
                with os.fdopen(descriptor, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(updated)
                    stream.flush()
                    os.fsync(stream.fileno())
            if _file(RULES_V4) != original or _runtime()[0] != rules:
                raise OperationError('Firewall changed during preflight; inspect locally and retry.')
            if runtime_state != 'managed':
                _command(['iptables', '-w', '10', '-I', 'INPUT', str(len(rules)), *WEB_RULE[2:]])
                expected = [*rules[:-1], WEB_RULE, rules[-1]]
                if _runtime()[0] != expected:
                    raise OperationError('Cannot verify the narrow INPUT addition; inspect locally and retry.')
            if temporary is not None:
                if _file(RULES_V4) != original:
                    raise OperationError('Persistence changed after the runtime addition; inspect locally and retry.')
                os.replace(temporary, RULES_V4)
                temporary = None
                _sync_directory(RULES_V4.parent)
        _report(kind)
    except (OSError, UnicodeError):
        raise OperationError(
            'Could not safely back up/persist firewall changes; check paths and disk locally, then retry. '
            'Any completed narrow runtime addition is retained; no bulk save/reload was attempted.'
        ) from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
