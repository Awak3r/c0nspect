#!/usr/bin/env python3
"""First installation on a Linux amd64 server; normal updates belong to Actions.

plan is offline/read-only. install requires --yes, creates a private installation
once, and can resume only that same installation. Host proxies, DNS, firewall,
existing Docker engines and existing Conspect deployments are never rewritten.
Run --help, then plan with the approved image/source before running install.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
from http.cookies import CookieError, SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import sys
import tempfile
from urllib.parse import urlencode, urlsplit

import operations
from backup import create_backup
from check_mcp import check_mcp
from operations import Compose, OperationError, operation_lock, run_command, validate_bundle
from prerequisites import check_local_docker, ensure_prerequisites
from release import IMAGE_PATTERN, atomic_write, compose_command, deployment_files, trusted_directory

DEFAULT_ROOT = Path('/opt/conspect')
SOURCE = Path(__file__).resolve().parent.parent
FORMAT = 1
PROJECT_LOCK = Path('/run/conspect-bootstrap.lock')
OWNERSHIP_LABEL = 'io.conspect.installation'
INPUT_FIELDS = ('url', 'image', 'revision', 'proxy', 'port')
ENV_FIELDS = {
    'CONSPECT_IMAGE', 'CONSPECT_HTTP_PORT', 'CONSPECT_INSTALLATION_ID', 'DATABASE_URL', 'POSTGRES_USER',
    'POSTGRES_DB', 'POSTGRES_PASSWORD', 'APP_SECRET', 'OWNER_USERNAME',
    'OWNER_PASSWORD', 'APP_BASE_URL', 'MCP_ENABLED', 'MCP_API_URL',
    'MAX_MARKDOWN_BYTES', 'MAX_IMAGE_BYTES', 'MAX_STORAGE_BYTES',
}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise OperationError('Invalid bootstrap arguments; use --help. Never put secrets in arguments.')


def absolute_path(raw):
    path = Path(raw)
    if not path.is_absolute() or '..' in path.parts or any(ord(c) < 32 for c in str(path)) or path == Path('/'):
        raise OperationError('Use a normalized absolute, non-root installation/source path.')
    return path


def public_origin(raw):
    invalid = OperationError('URL must be a canonical HTTPS origin without credentials, path, query or fragment.')
    if any(ord(c) <= 32 or ord(c) >= 127 for c in raw) or any(c in raw for c in '%?#\\'):
        raise invalid
    try:
        url = urlsplit(raw)
        if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None:
            raise ValueError
        if url.path not in ('', '/') or url.netloc.endswith(':'):
            raise ValueError
        host = url.hostname.lower()
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise invalid
            host = '[' + address.compressed + ']' if address.version == 6 else address.compressed
        except ValueError:
            if len(host) > 253 or '.' not in host or not all(
                re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')
            ):
                raise invalid from None
        port = url.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        return 'https://' + host + (':' + str(port) if port not in (None, 443) else '')
    except ValueError:
        raise invalid from None


def validate_options(args):
    args.root = absolute_path(args.root)
    if args.command == 'verify':
        return
    args.source = absolute_path(args.source)
    if args.source == args.root or args.source in args.root.parents or args.root in args.source.parents:
        raise OperationError('Stage source separately from the installation; neither path may contain the other.')
    args.url = public_origin(args.url)
    if not re.fullmatch(IMAGE_PATTERN, args.image) or not re.fullmatch('[0-9a-f]{40}', args.revision):
        raise OperationError('Choose an approved Conspect GHCR sha256 digest and its full 40-hex Git revision.')
    if not 1024 <= args.port <= 65535:
        raise OperationError('The loopback app port must be between 1024 and 65535.')
    if args.proxy == 'nginx' and urlsplit(args.url).port not in (None, 443):
        raise OperationError('The nginx template requires HTTPS port 443; use external mode for a custom public port.')
    if args.proxy in ('caddy', 'nginx'):
        try:
            ipaddress.ip_address(urlsplit(args.url).hostname)
        except ValueError:
            pass
        else:
            raise OperationError('For HTTPS directly by IP, use external mode with an already trusted IP certificate.')


def private_file(path):
    trusted_directory(path.parent)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError
        if info.st_size > 2 * 1024 * 1024:
            raise ValueError
        return path.read_bytes()
    except (OSError, ValueError):
        raise OperationError('Expected a private, root-owned, bounded regular installation file; symlinks are refused.') from None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_files(args, *, trusted):
    if trusted:
        trusted_directory(args.source)
        trusted_directory(args.source / 'deploy')
        for directory in (args.source / 'deploy').rglob('*'):
            if directory.is_symlink():
                raise OperationError('Deployment source directories may not contain symbolic links.')
            if directory.is_dir():
                trusted_directory(directory)
    files = deployment_files(args.source, args.root)
    if not (args.source / 'deploy/compose.nginx.yaml').is_file():
        raise OperationError('Source must include compose.yaml and the production overlay.')
    result = {}
    for source, target in files:
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024
                or trusted and (info.st_uid != 0 or info.st_mode & 0o022)):
            raise OperationError('Deployment sources must be bounded, regular root-owned files, not writable by others.')
        result[str(target.relative_to(args.root))] = source.read_bytes()
    return result


def generated_files(args, installation_id):
    database_password = secrets.token_hex(32)
    owner_password = secrets.token_urlsafe(24)
    environment = (
        'POSTGRES_DB=conspect\nPOSTGRES_USER=conspect\n'
        f'POSTGRES_PASSWORD={database_password}\n'
        f'DATABASE_URL=postgres://conspect:{database_password}@db:5432/conspect?sslmode=disable\n'
        f'APP_SECRET={secrets.token_hex(32)}\nOWNER_USERNAME=admin\nOWNER_PASSWORD={owner_password}\n'
        f'APP_BASE_URL={args.url}\nCONSPECT_IMAGE={args.image}\n'
        f'CONSPECT_HTTP_PORT={args.port}\nCONSPECT_INSTALLATION_ID={installation_id}\nMCP_ENABLED=true\n'
    )
    login = f'URL: {args.url}/login\nUsername: admin\nPassword: {owner_password}\n'
    proxy_name, proxy = proxy_template(args)
    return {'.env': environment.encode(), 'owner-login.txt': login.encode(), 'proxy/' + proxy_name: proxy.encode()}


def proxy_template(args):
    if args.proxy == 'caddy':
        return 'conspect.caddy', (
            '# Review and add only this independent site to your existing Caddy configuration.\n'
            '# Do not replace the global/NaiveProxy configuration or restart it blindly.\n'
            f'{args.url} {{\n'
            f'    reverse_proxy 127.0.0.1:{args.port} {{\n'
            '        header_up X-Forwarded-For {remote_host}\n'
            '        header_up X-Forwarded-Proto {scheme}\n'
            '    }\n}\n'
        )
    if args.proxy == 'nginx':
        text = (args.source / 'deploy/nginx.tls.conf').read_text(encoding='utf-8')
        return 'conspect.nginx.conf', text.replace('notes.example.com', urlsplit(args.url).hostname).replace(
            '127.0.0.1:8096', '127.0.0.1:' + str(args.port))
    return 'instructions.txt', (
        f'Public origin: {args.url}\nUpstream: http://127.0.0.1:{args.port}\n'
        'Expose the entire origin, including /login, /mcp, /oauth/* and /.well-known/*.\n'
        'Preserve the original Host and set X-Forwarded-Proto=https.\n'
        'Overwrite X-Forwarded-For with the client address; do not trust caller-supplied forwarding headers.\n'
        'Use a publicly trusted TLS certificate. Do not add another login/challenge in front of MCP/OAuth.\n'
        'The database must remain unpublished. Do not expose port 8096 directly to the internet.\n'
    )


def inputs(args):
    return {name: getattr(args, name) for name in INPUT_FIELDS}


def read_state(root):
    try:
        state = json.loads(private_file(root / '.bootstrap.json'))
        if (not isinstance(state, dict) or state.get('format') != FORMAT
                or not isinstance(state.get('inputs'), dict) or not isinstance(state.get('files'), dict)
                or not re.fullmatch('[0-9a-f]{32}', state.get('installation_id', ''))):
            raise ValueError
        return state
    except (ValueError, TypeError):
        raise OperationError('Bootstrap marker is invalid; inspect the installation privately. Nothing will be adopted.') from None


def inspect_target(args, files):
    if not os.path.lexists(args.root):
        return None
    trusted_directory(args.root)
    if not os.path.lexists(args.root / '.bootstrap.json'):
        raise OperationError('Target already exists without a bootstrap marker. Use Actions for updates; refusing adoption or overwrite.')
    state = read_state(args.root)
    if state['inputs'] != inputs(args):
        raise OperationError('Bootstrap inputs differ from this installation. Use the original inputs to resume, or Actions for updates.')
    expected_sources = {name: digest(data) for name, data in files.items()}
    actual_sources = {name: value for name, value in state['files'].items() if name == 'compose.yaml' or name.startswith('deploy/')}
    if actual_sources != expected_sources:
        raise OperationError('Deployment sources changed since bootstrap. Resume using the same approved source, or update through Actions.')
    for name, checksum in state['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or not isinstance(checksum, str):
            raise OperationError('Invalid bootstrap file manifest; refusing resume.')
        # Generated credentials and source are immutable for bootstrap resumes.
        if digest(private_file(args.root / path)) != checksum:
            raise OperationError('Installation files changed since bootstrap. They will not be overwritten; use verify or the update/recovery runbook.')
    return state


@contextmanager
def bootstrap_lock(root):
    # All roots use the fixed Docker project: serialize even different destinations.
    trusted_directory(PROJECT_LOCK.parent)
    path = PROJECT_LOCK
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise OperationError('Unsafe bootstrap lock file.')
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OperationError('Another bootstrap is running for this installation.') from None
        yield


def stage_installation(args, files):
    stage = Path(tempfile.mkdtemp(prefix='.conspect-bootstrap-', dir=args.root.parent))
    try:
        installation_id = secrets.token_bytes(16).hex()
        all_files = {**files, **generated_files(args, installation_id)}
        for name, data in all_files.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            # Private sources also avoid accidental credential exposure in future diagnostics.
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        state = {'format': FORMAT, 'inputs': inputs(args), 'status': 'prepared', 'installation_id': installation_id,
                 'files': {name: digest(data) for name, data in all_files.items()}}
        atomic_write(stage / '.bootstrap.json', json.dumps(state, indent=2) + '\n')
        if os.path.lexists(args.root):
            raise OperationError('Target appeared during installation; refusing to overwrite it.')
        stage.rename(args.root)
        return state
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def no_existing_resources():
    containers = run_command(['docker', 'ps', '--all', '--filter', 'label=com.docker.compose.project=conspect',
                              '--format', '{{.ID}}'], timeout=30)
    names = run_command(['docker', 'ps', '--all', '--format', '{{.Names}}'], timeout=30).splitlines()
    volumes = run_command(['docker', 'volume', 'ls', '--format', '{{.Name}}'], timeout=30).splitlines()
    networks = run_command(['docker', 'network', 'ls', '--format', '{{.Name}}'], timeout=30).splitlines()
    if (containers.strip() or any(name.startswith('conspect-') for name in names)
            or {'conspect_db_data', 'conspect_uploads'}.intersection(volumes)
            or {'conspect_backend', 'conspect_frontend'}.intersection(networks)):
        raise OperationError('Conspect containers, volumes or networks already exist. Refusing to attach old data to new secrets; use recovery instead.')


def owned_resources(root, state):
    """Check every retained project resource BEFORE Compose can recreate/adopt it."""
    identity = state['installation_id']
    containers = run_command(['docker', 'ps', '--all', '--filter', 'label=com.docker.compose.project=conspect',
                              '--format', '{{.ID}}'], timeout=30).split()
    names = run_command(['docker', 'ps', '--all', '--format', '{{.Names}}'], timeout=30).splitlines()
    for name in names:
        if name.startswith('conspect-') and name not in ('conspect-app-1', 'conspect-db-1'):
            raise OperationError('Unexpected Conspect containers exist; resolve the competing operation before resuming.')
    for identifier in set(containers).union(name for name in names if name in ('conspect-app-1', 'conspect-db-1')):
        item = json.loads(run_command(['docker', 'inspect', identifier], timeout=30))[0]
        labels = item['Config'].get('Labels') or {}
        if (labels.get(OWNERSHIP_LABEL) != identity
                or labels.get('com.docker.compose.project.working_dir') != str(root)
                or labels.get('com.docker.compose.project') != 'conspect'):
            raise OperationError('Retained containers belong to a different installation; refusing to recreate or adopt them.')
    for kind, expected in (('volume', {'conspect_db_data', 'conspect_uploads'}),
                           ('network', {'conspect_frontend', 'conspect_backend'})):
        names = run_command(['docker', kind, 'ls', '--format', '{{.Name}}'], timeout=30).splitlines()
        for name in expected.intersection(names):
            item = json.loads(run_command(['docker', kind, 'inspect', name], timeout=30))[0]
            labels = item.get('Labels') or {}
            if labels.get(OWNERSHIP_LABEL) != identity or labels.get('com.docker.compose.project') != 'conspect':
                raise OperationError('Retained volumes/networks lack this installation identity; refusing ambiguous data adoption.')


def existing_configuration(compose):
    for service, expected, fields in (
        ('app', compose.app_env, ('APP_SECRET', 'DATABASE_URL', 'APP_BASE_URL', 'DATA_DIR')),
        ('db', compose.db_env, ('POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD')),
    ):
        container = compose.container(service)
        if container:
            actual = dict(value.split('=', 1) for value in container['Config']['Env'])
            if any(actual.get(name) != expected.get(name) for name in fields):
                raise OperationError('Existing container configuration does not match bootstrap secrets; no container was changed.')
            if service == 'app' and container['Image'] != compose.image_id:
                raise OperationError('Existing app uses a different image; bootstrap is not an update tool.')


def verified_backup(root, state):
    if not state or 'backup' not in state:
        raise OperationError('Initial backup is incomplete. Resume install with the original inputs before verifying completion.')
    backup = Path(state['backup'])
    if backup.is_absolute() or '..' in backup.parts or backup.parts[:1] != ('backups',):
        raise OperationError('Invalid bootstrap backup pointer.')
    trusted_directory((root / backup).parent)
    trusted_directory(root / backup)
    validate_bundle(root / backup)


def free_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.bind(('127.0.0.1', port))
    except OSError:
        raise OperationError('The selected loopback app port is occupied; choose a free --port. Existing services will not be stopped.') from None


def check_resources(root):
    try:
        memory = next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))
        if int(memory) < 768 * 1024 or shutil.disk_usage(root.parent).free < 2 * 1024 ** 3:
            raise OperationError('Bootstrap requires at least 768 MiB RAM and 2 GiB free disk as a starting budget; allow more room for data and backups.')
    except (OSError, ValueError, StopIteration):
        raise OperationError('Cannot inspect server RAM/free disk; check resources before installation.') from None


def clear_overrides():
    for name in list(os.environ):
        if name.startswith(('DOCKER_', 'COMPOSE_')) or name in ENV_FIELDS:
            os.environ.pop(name, None)


def check_local(compose, root):
    compose.preflight(backup=True)
    for service in ('app', 'db'):
        container = compose.container(service)
        if (not container or container['State']['Status'] != 'running'
                or container['State'].get('Health', {}).get('Status') != 'healthy'):
            raise OperationError('Both app and db must report healthy before bootstrap can finish.')
        labels = container['Config'].get('Labels', {})
        if labels.get('com.docker.compose.project.working_dir') != str(root):
            raise OperationError('An existing container belongs to a different installation directory; refusing adoption.')
    url = public_origin(compose.app_env.get('APP_BASE_URL', ''))
    if str(compose.app_env.get('MCP_ENABLED', '')).lower() != 'true':
        raise OperationError('Bootstrap expects remote MCP enabled; inspect the private configuration.')
    return url


def save_state(root, state, status):
    state['status'] = status
    atomic_write(root / '.bootstrap.json', json.dumps(state, indent=2) + '\n')


def public_owner_check(root, url):
    """Correlate the public origin with this DB, not just generic discovery metadata.

    The random bootstrap login is sent only over verified HTTPS, without redirects
    or ambient proxies. No owner credentials, cookies or HTML are logged.
    """
    login = dict(line.split(': ', 1) for line in private_file(root / 'owner-login.txt').decode('utf-8').splitlines())
    origin = urlsplit(url)
    connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=15)
    try:
        connection.request('POST', '/login', body=urlencode({'username': login['Username'], 'password': login['Password']}),
                           headers={'Origin': url, 'Content-Type': 'application/x-www-form-urlencoded'})
        response = connection.getresponse()
        cookie = SimpleCookie()
        cookie.load(response.getheader('Set-Cookie', ''))
        session = cookie.get('conspect_session')
        # Never follow a Location or print server-supplied cookies/HTML.
        if (response.status != 303 or response.getheader('Location') != '/projects'
                or session is None or not session['secure'] or not session['httponly']):
            raise OperationError('Public URL did not accept this installation owner; check DNS/proxy routing privately.')
        response.read(65537)
    except (OSError, http.client.HTTPException, CookieError, ValueError):
        raise OperationError('Could not correlate public HTTPS with this installation; check DNS/proxy routing.') from None
    finally:
        connection.close()


def finish_public(root, state, url):
    if state:
        verified_backup(root, state)
    try:
        check_mcp(url)
        if state:
            public_owner_check(root, url)
    except OperationError:
        if state:
            save_state(root, state, 'local-ready')
        print('LOCAL_READY: app/db are healthy, but public HTTPS/MCP acceptance has not passed.')
        print('Review the generated proxy fragment, connect the full HTTPS origin, then run verify.')
        print('No host proxy, DNS or firewall was modified; containers remain available on loopback.')
        return 2
    if state:
        save_state(root, state, 'healthy')
    print('HEALTHY: public HTTPS readiness, OAuth discovery and MCP challenge passed.')
    return 0


def install(args):
    if not args.yes:
        raise OperationError('Installation requires --yes. Run plan and review the intended changes first.')
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise OperationError('Run install as root on the target Linux server.')
    clear_overrides()
    trusted_directory(args.root.parent)
    files = source_files(args, trusted=True)
    # Refuse unmanaged installations before installing packages or touching services.
    inspect_target(args, files)
    with bootstrap_lock(args.root):
        state = inspect_target(args, files)
        check_resources(args.root)
        if state is None:
            free_port(args.port)
        # Inspect an existing daemon before allowing system-wide plugin changes.
        if shutil.which('docker'):
            check_local_docker()
            if state is None:
                no_existing_resources()
            else:
                owned_resources(args.root, state)
        ensure_prerequisites(install=args.install_deps)
        if state is None:
            no_existing_resources()
            state = stage_installation(args, files)
        previous_root = operations.ROOT
        operations.ROOT = args.root
        try:
            with operation_lock():
                # Recheck manifest while serialized with releases and backups.
                state = inspect_target(args, files)
                owned_resources(args.root, state)
                command = compose_command(args.root)
                # Validate interpolation before network pulls or container creation.
                run_command(command + ['config', '--quiet'], timeout=30)
                run_command(['docker', 'pull', '--platform', 'linux/amd64', args.image], timeout=300)
                if not run_command(command + ['ps', '--all', '--quiet', 'db'], timeout=30).strip():
                    run_command(command + ['pull', 'db'], timeout=300)
                compose = Compose(nginx=True)
                existing_configuration(compose)
                save_state(args.root, state, 'starting')
                # A retry may start existing containers but must never replace a DB
                # just because another operation pulled a newer mutable PG17 tag.
                run_command(command + ['up', '--detach', '--no-recreate', '--no-build', '--pull', 'never', '--wait',
                                       '--wait-timeout', '180', 'app', 'db'], timeout=240)
                compose = Compose(nginx=True)
                url = check_local(compose, args.root)
                save_state(args.root, state, 'local-ready')
                if 'backup' not in state:
                    backup = create_backup(compose, args.root / 'backups')
                    validate_bundle(backup)
                    state['backup'] = str(backup.relative_to(args.root))
                    save_state(args.root, state, 'local-ready')
                else:
                    verified_backup(args.root, state)
                print('Private owner credentials: ' + str(args.root / 'owner-login.txt'))
                print('Proxy fragment directory: ' + str(args.root / 'proxy'))
                print('Initial verified backup is LOCAL ONLY; configure an encrypted offsite copy separately.')
                return finish_public(args.root, state, url)
        finally:
            operations.ROOT = previous_root


def verify(args):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise OperationError('Run verify as root on the target Linux server.')
    clear_overrides()
    trusted_directory(args.root)
    private_file(args.root / '.env')
    ensure_prerequisites()
    previous_root = operations.ROOT
    operations.ROOT = args.root
    try:
        with operation_lock():
            compose = Compose(nginx=True)
            url = check_local(compose, args.root)
            state = read_state(args.root) if os.path.lexists(args.root / '.bootstrap.json') else None
            if state:
                owned_resources(args.root, state)
            return finish_public(args.root, state, url)
    finally:
        operations.ROOT = previous_root


def plan(args):
    files = source_files(args, trusted=False)
    print('PLAN ONLY: no commands, downloads, credentials or installation files are created.')
    print('Target: ' + str(args.root))
    print('Public origin: ' + args.url)
    print('Image: ' + args.image + '; revision: ' + args.revision)
    print('Source files to stage: ' + str(len(files)))
    print('Existing target: ' + ('yes; install will require an unchanged bootstrap marker' if os.path.lexists(args.root) else 'no'))
    print('Docker client on PATH: ' + ('yes; daemon/capabilities checked during install' if shutil.which('docker') else 'missing'))
    print('Install will check linux/amd64, local Docker, Compose start/up --wait, RAM, disk and loopback port.')
    print('Install will generate credentials ONCE, start only app/db and take a consistent local backup.')
    print('Proxy mode: ' + args.proxy + '; only a reviewable fragment is generated, no host service changes.')
    print('Exit 0 requires public HTTPS/MCP acceptance; exit 2 means LOCAL_READY, not a working public site.')
    return 0


def main(argv=None):
    parser = SafeParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True, parser_class=SafeParser)
    for name in ('plan', 'install', 'verify'):
        command = commands.add_parser(name)
        command.add_argument('--root', default=str(DEFAULT_ROOT))
        if name != 'verify':
            command.add_argument('--source', default=str(SOURCE))
            command.add_argument('--url', required=True)
            command.add_argument('--image', required=True, help='Approved immutable GHCR digest, never latest/a mutable tag')
            command.add_argument('--revision', required=True, help='Full Git SHA matching the approved source/image')
            command.add_argument('--proxy', choices=('caddy', 'nginx', 'external'), required=True)
            command.add_argument('--port', type=int, default=8096)
        if name == 'install':
            command.add_argument('--yes', action='store_true')
            command.add_argument('--install-deps', action='store_true', help='Opt in to prerequisite installation on Ubuntu 24.04 amd64')
    try:
        args = parser.parse_args(argv)
        validate_options(args)
        os.umask(0o077)
        return {'plan': plan, 'install': install, 'verify': verify}[args.command](args)
    except OperationError as error:
        print('Bootstrap refused/failed: ' + str(error), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        print('Bootstrap failed; details withheld to protect credentials. Retain the installation and inspect it before retrying.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
