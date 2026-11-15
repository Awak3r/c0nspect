"""Isolated host HTTPS tests: simulated ownership, commands and public HTTP only."""

import http.client
import json
import os
import socket
import subprocess
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import host_setup as host
import operations
from operations import OperationError

SOURCE = Path(__file__).parent
URL = 'https://notes.example.com'
DOMAIN = 'notes.example.com'
SECRET = 'synthetic-private-value-do-not-log'


class CommandFailure(OperationError):
    def __init__(self):
        super().__init__(SECRET)
        self.command_stderr = SECRET.encode()


class HostSetupTests(unittest.TestCase):
    def enter(self, context):
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='conspect-host-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'installation'
        self.root.mkdir(mode=0o700)
        self.owners = {}
        self.commands = []
        self.failures = {}
        self.programs = {'nginx', 'certbot', 'apt-get', 'ss', 'ps', 'systemctl'}
        self.processes = ''
        self.units = ''
        self.tcp = ''
        self.udp = ''
        self.extra_config = ''
        self.active = 'active'
        self.timer = 'enabled'
        self.fail_bootstrap = False
        self.fail_tls = False
        self.http_status = 200
        self.http_body = None
        self.http_error = None
        self.http_connections = []
        self.issue_error = None
        self.issue_interrupt = False
        self.reload_interrupt = False
        self.reloads = []
        self.bin = self.base / 'usr/sbin'
        self.bin.mkdir(parents=True)
        for name in self.programs:
            (self.bin / name).write_text('never executed')
        constants = {
            'SITES_AVAILABLE': self.base / 'etc/nginx/sites-available',
            'SITES_ENABLED': self.base / 'etc/nginx/sites-enabled',
            'ACME_ROOT': self.base / 'var/lib/conspect-acme',
            'LE_ROOT': self.base / 'etc/letsencrypt',
            'HOOK_DIRECTORY': self.base / 'etc/letsencrypt/renewal-hooks/deploy',
            'NGINX_BINARY': self.bin / 'nginx',
            'SYSTEMCTL_BINARY': self.bin / 'systemctl',
            'LOCK_DIRECTORY': self.base / 'run',
        }
        for name, value in constants.items():
            self.enter(patch.object(host, name, value))
        host.LOCK_DIRECTORY.mkdir()
        host.SITES_AVAILABLE.mkdir(parents=True)
        host.SITES_ENABLED.mkdir(parents=True)
        self.paths = host._paths(self.root, DOMAIN)
        self.marker = self.root / 'host/https.json'
        (self.root / 'deploy').mkdir()
        (self.root / 'proxy').mkdir()
        (self.root / 'deploy/nginx.bootstrap.conf').write_bytes((SOURCE / 'nginx.bootstrap.conf').read_bytes())
        final = (SOURCE / 'nginx.tls.conf').read_text().replace('/etc/letsencrypt', str(host.LE_ROOT)).replace(
            '/var/lib/conspect-acme', str(host.ACME_ROOT))
        (self.root / 'proxy/conspect.nginx.conf').write_text(final)

        # Real filesystem types/modes/atomic replacement; no actual chown/root needed.
        real_stat = Path.stat
        parents = set(self.base.parents)

        def owned_stat(path, *, follow_symlinks=True):
            info = list(real_stat(path, follow_symlinks=follow_symlinks))
            if path == self.base or self.base in path.parents:
                info[4] = self.owners.get(path, 0)
            elif path in parents:
                info[4] = 0
                info[0] = int(info[0]) & ~0o022
            return os.stat_result(info)

        self.enter(patch.object(Path, 'stat', owned_stat))
        real_resolve = Path.resolve

        def resolve(path, strict=False):
            if str(path).startswith('/proc/'):
                if str(path) == '/proc/123/exe':
                    return self.bin / 'nginx'
                raise OSError(SECRET)
            return real_resolve(path, strict=strict)

        self.enter(patch.object(Path, 'resolve', resolve))
        self.enter(patch.object(host.platform, 'system', return_value='Linux'))
        self.enter(patch.object(host.platform, 'machine', return_value='x86_64'))
        self.enter(patch.object(host.platform, 'freedesktop_os_release', return_value={
            'ID': 'ubuntu', 'VERSION_ID': '24.04',
        }))
        self.enter(patch.object(host.os, 'geteuid', return_value=0))
        self.enter(patch.object(host.shutil, 'which', side_effect=lambda name: str(self.bin / name) if name in self.programs else None))
        self.enter(patch.object(subprocess, 'run', side_effect=AssertionError('No real subprocess allowed')))
        self.enter(patch.object(operations, 'run_command', side_effect=AssertionError('No real command allowed')))
        self.enter(patch.object(host, 'run_command', side_effect=self.command))
        self.enter(patch.object(socket, 'create_connection', side_effect=AssertionError('No real network allowed')))
        self.enter(patch.object(http.client, 'HTTPConnection', side_effect=self.http_connection))

    def command(self, arguments, *, stdin, timeout):
        self.assertEqual(stdin, subprocess.DEVNULL)
        self.assertGreater(timeout, 0)
        self.commands.append(list(arguments))
        if tuple(arguments) in self.failures:
            raise self.failures[tuple(arguments)]
        if arguments == ['ps', '-eo', 'comm=']:
            return self.processes
        if arguments[:2] == ['systemctl', 'list-units']:
            return self.units
        if arguments == ['ss', '-H', '-ltnp']:
            return self.tcp
        if arguments == ['ss', '-H', '-lunp']:
            return self.udp
        if arguments == ['nginx', '-T']:
            output = f'# configuration file /etc/nginx/nginx.conf:\ninclude {host.SITES_ENABLED}/*;\n' + self.extra_config
            if self.paths['enabled'].exists():
                output += f'\n# configuration file {self.paths["enabled"]}:\n' + self.paths['site'].read_text()
            return output
        if arguments == ['nginx', '-t']:
            text = self.paths['site'].read_text() if self.paths['site'].exists() else ''
            if (self.fail_tls and 'ssl_certificate' in text) or (self.fail_bootstrap and text and 'ssl_certificate' not in text):
                raise OperationError(SECRET)
            return ''
        if arguments == ['systemctl', 'is-enabled', 'certbot.timer']:
            return self.timer
        if arguments == ['systemctl', 'show', '--property=ActiveState', '--value', 'nginx']:
            return self.active
        if arguments == ['systemctl', 'reload', 'nginx']:
            self.reloads.append(self.paths['site'].read_bytes())
            if self.reload_interrupt:
                self.reload_interrupt = False
                raise KeyboardInterrupt
            return ''
        if arguments == ['systemctl', 'enable', '--now', 'nginx']:
            self.active = 'active'
            return ''
        if arguments == ['systemctl', 'enable', '--now', 'certbot.timer']:
            self.timer = 'enabled'
            return ''
        if arguments[:4] == ['env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'apt-get']:
            if arguments[4] == 'install':
                for package in ('nginx', 'certbot'):
                    if package in arguments:
                        self.programs.add(package)
            return ''
        if arguments[:2] == ['certbot', 'certonly']:
            if self.issue_error:
                raise self.issue_error
            self.certificates()
            if self.issue_interrupt:
                self.issue_interrupt = False
                raise KeyboardInterrupt
            return ''
        raise AssertionError('Unexpected command: ' + repr(arguments))

    def certificates(self):
        live = host.LE_ROOT / 'live' / DOMAIN
        archive = host.LE_ROOT / 'archive' / DOMAIN
        live.mkdir(parents=True, exist_ok=True)
        archive.mkdir(parents=True, exist_ok=True)
        for name in ('fullchain', 'privkey'):
            path = archive / (name + '1.pem')
            path.write_text('synthetic certificate/key; never real')
            path.chmod(0o600 if name == 'privkey' else 0o644)
            link = live / (name + '.pem')
            if not link.is_symlink():
                link.symlink_to('../../archive/' + DOMAIN + '/' + name + '1.pem')

    def http_connection(self, hostname, port, *, timeout):
        self.assertEqual((hostname, port), (DOMAIN, 80))
        self.assertGreater(timeout, 0)
        if self.http_error:
            raise self.http_error
        connection = Mock()
        self.http_connections.append(connection)

        def request(method, path, *, headers):
            self.assertEqual(method, 'GET')
            self.assertEqual(headers, {'Connection': 'close'})
            probe = host.ACME_ROOT / path.lstrip('/')
            self.assertEqual(probe.stat().st_mode & 0o777, 0o644)
            body = probe.read_bytes() if self.http_body is None else self.http_body
            response = Mock(status=self.http_status)
            response.read.side_effect = lambda maximum: body[:maximum]
            connection.getresponse.return_value = response

        connection.request.side_effect = request
        return connection

    def configure(self, **options):
        return host.configure_https(self.root, URL, 8096, agree_tos=True, **options)

    def state(self):
        return json.loads(self.marker.read_text())

    def assert_read_only(self, before):
        after = {str(p.relative_to(self.base)): (p.lstat().st_mode, os.readlink(p) if p.is_symlink() else p.read_bytes())
                 for p in self.base.rglob('*') if not p.is_dir() or p.is_symlink()}
        self.assertEqual(before, after)
        self.assertFalse(any(c[0] in ('env', 'certbot') or c[:2] == ['systemctl', 'reload'] for c in self.commands))

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.lstat().st_mode, os.readlink(p) if p.is_symlink() else p.read_bytes())
                for p in self.base.rglob('*') if not p.is_dir() or p.is_symlink()}

    def test_inspect_is_read_only_before_staging_and_reports_missing(self):
        self.programs -= {'nginx', 'certbot'}
        root = self.base / 'not-staged'
        before = self.snapshot()
        self.assertEqual(host.inspect_host(root, URL, 8096), {'missing_dependencies': ['nginx', 'certbot']})
        self.assert_read_only(before)
        self.assertFalse(root.exists())

    def test_consent_precedes_all_checks_and_changes(self):
        with self.assertRaisesRegex(OperationError, 'agree_tos=True'):
            host.configure_https(self.root, URL, 8096, install_dependencies=True)
        self.assertEqual(self.commands, [])
        self.assertFalse(self.marker.parent.exists())

    def test_revalidate_url_port_and_email_before_commands(self):
        for url in ('http://notes.example.com', 'https://Notes.example.com', 'https://notes.example.com:443',
                    'https://notes.example.com:8443', 'https://notes.example.com/', 'https://127.0.0.1',
                    'https://[::1]', 'https://user@notes.example.com', 'https://x.example;return 200;',
                    'https://x.example\nfoo', 'https://x.example%0a', 'https://x.example?q=1',
                    'https://x.example#x', 'https://x.example\\foo', 'https://x..example', 'https://x.example.'):
            with self.subTest(url=url), self.assertRaises(OperationError):
                host.configure_https(self.root, url, 8096, agree_tos=True)
        for port in ('8096', True, 80, 65536):
            with self.subTest(port=port), self.assertRaises(OperationError):
                host.inspect_host(self.root, URL, port)
        for email in ('--flag@example.com', 'a@example.com\n--flag', 'not-an-email'):
            with self.subTest(email=email), self.assertRaises(OperationError):
                self.configure(email=email)
        self.assertEqual(self.commands, [])

    def test_conflicting_process_binary_service_or_port_refused_before_packages(self):
        conflicts = [
            ('processes', 'caddy\n'), ('processes', 'apache2\n'), ('units', 'caddy.service loaded inactive dead\n'),
            ('tcp', 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=123,fd=4))'),
            ('tcp', 'LISTEN 0 128 [::]:80 [::]:*'),
            ('tcp', 'LISTEN 0 128 *:80 *:* users:(("nginx",pid=666,fd=4))'),
            ('tcp', 'LISTEN 0 128 *:80 *:* users:(("nginx",pid=123,fd=4),("vpn",pid=1,fd=5))'),
            ('udp', 'UNCONN 0 0 *:443 *:* users:(("vpn",pid=123,fd=4))'),
        ]
        self.programs -= {'nginx', 'certbot'}
        for attribute, value in conflicts:
            with self.subTest(attribute=attribute, value=value):
                setattr(self, attribute, value)
                self.commands.clear()
                before = self.snapshot()
                with self.assertRaises(OperationError):
                    self.configure(install_dependencies=True)
                self.assert_read_only(before)
                self.assertFalse(self.marker.parent.exists())
                setattr(self, attribute, '')
        self.programs.add('apache2')
        with self.assertRaises(OperationError):
            self.configure(install_dependencies=True)
        self.assertFalse(self.marker.parent.exists())

    def test_existing_nginx_and_unrelated_sites_preserved(self):
        other = host.SITES_AVAILABLE / 'other.conf'
        other.write_text('server { listen 80; server_name other.example.com; }')
        (host.SITES_ENABLED / 'other.conf').symlink_to(other)
        self.extra_config = f'# configuration file {other}:\n' + other.read_text()
        self.tcp = 'LISTEN 0 128 *:80 *:* users:(("nginx",pid=123,fd=4))'
        old = other.read_bytes()
        self.configure()
        self.assertEqual(other.read_bytes(), old)
        self.assertEqual(os.readlink(host.SITES_ENABLED / 'other.conf'), str(other))
        self.assertEqual(self.state()['stage'], 'tls')
        self.assertEqual(self.paths['backup'].read_bytes(), self.reloads[0])
        self.assertEqual(len(self.reloads), 2)
        self.assertFalse(any('restart' in c or c[0] == 'env' or c[0] == 'docker' for c in self.commands))

    def test_full_flow_private_state_scoped_hook_and_idempotent(self):
        self.configure(email='owner@example.com')
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.marker.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.paths['backup'].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.paths['hook'].stat().st_mode & 0o777, 0o700)
        self.assertEqual(os.readlink(self.paths['enabled']), str(self.paths['site']))
        hook = self.paths['hook'].read_text()
        self.assertIn('${RENEWED_LINEAGE:-}', hook)
        self.assertIn(str(host.LE_ROOT / 'live' / DOMAIN), hook)
        self.assertIn('-t >/dev/null 2>&1 && ', hook)
        self.assertIn('reload nginx', hook)
        issuance = next(c for c in self.commands if c[0] == 'certbot')
        self.assertIn('--webroot', issuance)
        self.assertIn('--agree-tos', issuance)
        self.assertNotIn('--nginx', issuance)
        self.assertEqual(issuance[-2:], ['--email', 'owner@example.com'])
        self.assertEqual(len(self.http_connections), 1)
        self.assertFalse(list((host.ACME_ROOT / '.well-known/acme-challenge').iterdir()))
        before = self.snapshot()
        self.commands.clear()
        self.configure()
        self.assert_read_only(before)
        self.assertEqual(len(self.reloads), 2)
        self.assertEqual(len(self.http_connections), 1)

    def test_existing_certificate_skips_http_and_certbot(self):
        self.certificates()
        self.configure()
        self.assertFalse(self.http_connections)
        self.assertFalse(any(c[0] == 'certbot' for c in self.commands))
        self.assertEqual(len(self.reloads), 1)
        self.assertFalse(self.paths['backup'].exists())

    def test_probe_failures_do_not_issue_and_leave_resumable_bootstrap(self):
        for status, body, error in ((301, None, None), (200, b'wrong-host', None), (200, None, OSError(SECRET))):
            with self.subTest(status=status, body=body, error=error):
                self.http_status, self.http_body, self.http_error = status, body, error
                self.commands.clear()
                with self.assertRaisesRegex(OperationError, 'public DNS.*firewall'):
                    self.configure()
                self.assertEqual(self.state()['stage'], 'bootstrap')
                self.assertNotIn('ssl_certificate', self.paths['site'].read_text())
                self.assertFalse(any(c[0] == 'certbot' for c in self.commands))
                self.assertFalse(list((host.ACME_ROOT / '.well-known/acme-challenge').iterdir()))
        self.http_status, self.http_body, self.http_error = 200, None, None
        self.configure()
        self.assertEqual(self.state()['stage'], 'tls')
        issuance = next(c for c in self.commands if c[0] == 'certbot')
        self.assertEqual(issuance[-1], '--register-unsafely-without-email')

    def test_initial_nginx_validation_failure_removes_only_pending_site(self):
        self.fail_bootstrap = True
        with self.assertRaisesRegex(OperationError, 'previous configuration has been restored'):
            self.configure()
        self.assertEqual(self.state()['stage'], 'empty')
        self.assertIsNone(self.state()['pending'])
        self.assertFalse(self.paths['site'].exists())
        self.assertFalse(self.paths['enabled'].is_symlink())
        self.assertFalse(self.reloads)
        self.assertFalse(self.http_connections)
        self.fail_bootstrap = False
        self.configure()
        self.assertEqual(self.state()['stage'], 'tls')

    def test_tls_validation_failure_restores_bootstrap_without_reload(self):
        self.fail_tls = True
        with self.assertRaises(OperationError):
            self.configure()
        self.assertEqual(len(self.reloads), 1)
        self.assertEqual(self.paths['site'].read_bytes(), self.reloads[0])
        self.assertEqual(self.state()['stage'], 'bootstrap')
        self.assertFalse(self.paths['hook'].exists())
        self.assertFalse(self.paths['backup'].exists())
        self.fail_tls = False
        self.configure()
        self.assertEqual(self.state()['stage'], 'tls')
        self.assertEqual(self.paths['backup'].read_bytes(), self.reloads[0])

    def test_resume_after_issuance_and_after_pending_reload(self):
        self.issue_interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self.configure()
        self.assertEqual(self.state()['stage'], 'bootstrap')
        self.reload_interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self.configure()
        self.assertEqual(self.state()['stage'], 'bootstrap')
        self.assertEqual(self.state()['pending']['stage'], 'tls')
        self.configure()
        self.assertEqual(self.state()['stage'], 'tls')
        self.assertIsNone(self.state()['pending'])
        self.assertEqual(sum(c[0] == 'certbot' for c in self.commands), 1)

    def test_resume_each_journalled_partial_file_write_and_enable(self):
        real_apply = host._apply
        for stage in ('bootstrap', 'tls'):
            for after_name in ('backup', 'site', 'hook', 'enabled'):
                with self.subTest(stage=stage, after_name=after_name), tempfile.TemporaryDirectory(dir=self.base) as temporary:
                    root = Path(temporary) / 'installation'
                    root.mkdir(mode=0o700)
                    (root / 'deploy').mkdir()
                    (root / 'proxy').mkdir()
                    (root / 'deploy/nginx.bootstrap.conf').write_bytes((self.root / 'deploy/nginx.bootstrap.conf').read_bytes())
                    (root / 'proxy/conspect.nginx.conf').write_bytes((self.root / 'proxy/conspect.nginx.conf').read_bytes())
                    material = host._materials(root, DOMAIN, 8096)
                    state = {'version': 1, 'url': URL, 'port': 8096,
                             'hashes': {k: host._digest(v) for k, v in material.items()},
                             'stage': 'empty', 'backup': False, 'pending': None,
                             'new_nginx': False, 'new_certbot': False}
                    (root / 'host').mkdir(mode=0o700)
                    # Simulate the durable intent followed by a prefix of file mutations.
                    old_paths = self.paths
                    paths = host._paths(root, DOMAIN)
                    state['pending'] = {'stage': stage, 'backup': False}
                    host._save(root, state)
                    expected = host._expected(stage, False, material)
                    for name in ('backup', 'site', 'hook', 'enabled'):
                        if name == 'enabled' and expected[name]:
                            paths[name].symlink_to(paths['site'])
                        elif name != 'enabled' and expected[name] is not None:
                            paths[name].parent.mkdir(parents=True, exist_ok=True)
                            paths[name].write_bytes(expected[name])
                            paths[name].chmod(0o700 if name == 'hook' else 0o644)
                        if name == after_name:
                            break
                    recovered = host._ownership(root, DOMAIN, URL, 8096, material)
                    self.assertIsNotNone(recovered)
                    self.paths = paths
                    if stage == 'tls':
                        self.certificates()
                    host._transition(root, DOMAIN, URL, 8096, recovered, material, stage)
                    self.assertEqual(recovered['stage'], stage)
                    self.assertIsNone(recovered['pending'])
                    real_apply(paths, host._expected('empty', False, material))
                    self.paths = old_paths

    def test_preexisting_destinations_are_never_adopted(self):
        for name in ('site', 'enabled', 'hook', 'backup'):
            with self.subTest(name=name):
                path = self.paths[name]
                path.parent.mkdir(parents=True, exist_ok=True)
                if name == 'backup':
                    path.parent.chmod(0o700)
                path.write_text('unrelated config')
                path.chmod(0o600)
                before = self.snapshot()
                self.commands.clear()
                with self.assertRaises(OperationError):
                    self.configure(install_dependencies=True)
                self.assert_read_only(before)
                path.unlink()

    def test_matching_site_without_marker_is_still_unowned(self):
        material = host._materials(self.root, DOMAIN, 8096)
        self.paths['site'].write_bytes(material['bootstrap'])
        with self.assertRaises(OperationError):
            self.configure()
        self.assertFalse(self.marker.exists())

    def test_edited_owned_files_missing_files_and_templates_refused(self):
        self.configure()
        for path in (self.paths['site'], self.paths['hook'], self.paths['backup'],
                     self.root / 'deploy/nginx.bootstrap.conf', self.root / 'proxy/conspect.nginx.conf'):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b'\n# manual edit\n')
                self.commands.clear()
                before = self.snapshot()
                with self.assertRaises(OperationError):
                    self.configure()
                self.assert_read_only(before)
                path.write_bytes(original)
        self.paths['site'].unlink()
        with self.assertRaises(OperationError):
            self.configure()

    def test_symlink_replacement_and_state_permissions_refused(self):
        self.configure()
        self.paths['enabled'].unlink()
        self.paths['enabled'].symlink_to('/unrelated/site')
        with self.assertRaises(OperationError):
            self.configure()
        self.paths['enabled'].unlink()
        self.paths['enabled'].symlink_to(self.paths['site'])
        self.marker.chmod(0o644)
        with self.assertRaises(OperationError):
            self.configure()
        self.marker.chmod(0o600)
        self.marker.write_text('{"version": 999}')
        with self.assertRaises(OperationError):
            self.configure()

    def test_untrusted_directories_files_links_and_ownership_refused(self):
        for path in (self.root, self.root / 'deploy', host.SITES_AVAILABLE, host.SITES_ENABLED, host.LOCK_DIRECTORY):
            mode = path.stat().st_mode & 0o777
            path.chmod(0o777)
            with self.subTest(path=path), self.assertRaises(OperationError):
                self.configure(install_dependencies=True)
            path.chmod(mode)
        template = self.root / 'proxy/conspect.nginx.conf'
        self.owners[template] = 1000
        with self.assertRaises(OperationError):
            self.configure()
        del self.owners[template]
        link = self.root / 'deploy'
        actual = self.root / 'real-deploy'
        link.rename(actual)
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OperationError):
            self.configure()
        self.assertFalse(self.marker.exists())

    def test_certificate_symlinks_targets_key_modes_and_ancestors_checked(self):
        self.certificates()
        key = host.LE_ROOT / 'live' / DOMAIN / 'privkey.pem'
        target = os.readlink(key)
        key.unlink()
        key.symlink_to('/outside/secret')
        with self.assertRaises(OperationError):
            self.configure(install_dependencies=True)
        key.unlink()
        key.symlink_to(target)
        archive_key = host.LE_ROOT / 'archive' / DOMAIN / 'privkey1.pem'
        archive_key.chmod(0o644)
        with self.assertRaises(OperationError):
            self.configure()
        archive_key.chmod(0o600)
        self.owners[key] = 1000
        with self.assertRaises(OperationError):
            self.configure()
        del self.owners[key]
        archive_key.parent.chmod(0o777)
        with self.assertRaises(OperationError):
            self.configure()
        self.assertFalse(self.marker.exists())

    def test_hostname_conflicts_and_nonstandard_layout_are_read_only_failures(self):
        for names in ('notes.example.com', '"notes.example.com"', "'notes.example.com'", '*.example.com',
                      '~^notes', '$hostname', '\n notes.example.com\n'):
            self.extra_config = '# configuration file /etc/nginx/conf.d/other.conf:\nserver { server_name ' + names + '; }\n'
            with self.subTest(names=names), self.assertRaises(OperationError):
                self.configure()
            self.assertFalse(self.marker.exists())
        self.extra_config = ''
        self.failures[('nginx', '-T')] = OperationError(SECRET)
        with self.assertRaises(OperationError):
            self.configure()
        self.assertFalse(self.marker.exists())

    def test_missing_dependencies_require_opt_in(self):
        self.programs -= {'nginx', 'certbot'}
        with self.assertRaisesRegex(OperationError, 'Missing dependencies'):
            self.configure()
        self.assertFalse(self.marker.parent.exists())
        self.assertFalse(any(c[0] == 'env' for c in self.commands))

    def test_only_missing_packages_installed_and_only_new_timer_enabled(self):
        self.programs -= {'nginx', 'certbot'}
        self.active = 'inactive'
        self.timer = 'disabled'
        self.configure(install_dependencies=True)
        install = next(c for c in self.commands if c[:5] == [
            'env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'apt-get', 'install'])
        self.assertEqual(install[-2:], ['nginx', 'certbot'])
        self.assertIn('--no-remove', install)
        self.assertIn('--no-upgrade', install)
        self.assertIn(['systemctl', 'enable', '--now', 'certbot.timer'], self.commands)
        self.assertIn(['systemctl', 'enable', '--now', 'nginx'], self.commands)
        self.assertFalse(any('restart' in c or 'docker' in c for c in self.commands))
        self.commands.clear()
        self.configure(install_dependencies=True)
        self.assertFalse(any(c[0] == 'env' or 'enable' in c for c in self.commands))

    def test_existing_disabled_timer_and_stopped_nginx_never_changed(self):
        self.timer = 'disabled'
        with self.assertRaisesRegex(OperationError, 'timer'):
            self.configure(install_dependencies=True)
        self.assertFalse(self.marker.exists())
        self.timer = 'enabled'
        self.active = 'inactive'
        with self.assertRaisesRegex(OperationError, 'not active'):
            self.configure(install_dependencies=True)
        self.assertFalse(self.marker.exists())
        self.assertFalse(any('enable' in c or 'restart' in c or c[0] == 'env' for c in self.commands))

    def test_platform_and_root_checks(self):
        with patch.object(host.os, 'geteuid', return_value=1000), self.assertRaises(OperationError):
            host.inspect_host(self.root, URL, 8096)
        with patch.object(host.platform, 'system', return_value='Darwin'), self.assertRaises(OperationError):
            host.inspect_host(self.root, URL, 8096)
        self.programs.remove('certbot')
        with patch.object(host.platform, 'machine', return_value='aarch64'), self.assertRaisesRegex(OperationError, 'amd64'):
            self.configure(install_dependencies=True)
        self.assertFalse(any(c[0] == 'env' for c in self.commands))
        self.assertFalse(self.marker.parent.exists())

    def test_resume_interruption_between_package_install_and_timer_enable(self):
        self.programs -= {'nginx', 'certbot'}
        self.timer = 'disabled'
        self.active = 'inactive'
        key = ('systemctl', 'enable', '--now', 'certbot.timer')
        self.failures[key] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.configure(install_dependencies=True)
        self.assertTrue(self.state()['new_certbot'])
        self.assertTrue(self.state()['new_nginx'])
        self.assertEqual(self.state()['stage'], 'empty')
        self.failures.clear()
        self.commands.clear()
        with self.assertRaisesRegex(OperationError, 'timer'):
            self.configure()
        self.assertFalse(any('enable' in c for c in self.commands))
        self.configure(install_dependencies=True)
        self.assertEqual(self.state()['stage'], 'tls')
        self.assertFalse(self.state()['new_certbot'])
        self.assertFalse(self.state()['new_nginx'])
        self.assertFalse(any(c[0] == 'env' for c in self.commands))
        self.active = 'inactive'
        with self.assertRaisesRegex(OperationError, 'not active'):
            self.configure(install_dependencies=True)

    def test_probe_collision_never_removes_a_preexisting_file(self):
        directory = host.ACME_ROOT / '.well-known/acme-challenge'
        directory.mkdir(parents=True)
        collision = directory / ('conspect-' + 'a' * 32)
        collision.write_bytes(b'unrelated probe')
        with patch.object(host.secrets, 'token_hex', side_effect=['b' * 48, 'a' * 32]), self.assertRaises(OperationError):
            host._public_probe(DOMAIN)
        self.assertEqual(collision.read_bytes(), b'unrelated probe')
        self.assertFalse(self.http_connections)

    def test_nonstandard_nginx_include_is_not_rewritten(self):
        real_command = self.command

        def command(arguments, **kwargs):
            if arguments == ['nginx', '-T']:
                self.commands.append(list(arguments))
                return '# configuration file /etc/nginx/nginx.conf:\ninclude /etc/nginx/conf.d/*.conf;\n'
            return real_command(arguments, **kwargs)

        with patch.object(host, 'run_command', side_effect=command), self.assertRaisesRegex(OperationError, 'standard sites-enabled'):
            self.configure()
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.paths['site'].exists())

    def test_command_errors_and_probe_errors_never_expose_output(self):
        self.issue_error = CommandFailure()
        try:
            self.configure()
        except OperationError:
            rendered = traceback.format_exc()
        else:
            self.fail('Expected sanitized issuance failure')
        self.assertNotIn(SECRET, rendered)
        self.assertEqual(self.state()['stage'], 'bootstrap')
        self.issue_error = None
        self.http_error = OSError(SECRET)
        try:
            self.configure()
        except OperationError:
            rendered = traceback.format_exc()
        else:
            self.fail('Expected sanitized probe failure')
        self.assertNotIn(SECRET, rendered)


if __name__ == '__main__':
    unittest.main()
