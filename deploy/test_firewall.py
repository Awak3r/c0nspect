"""Temporary files and mocked commands only; never touch the host firewall."""

import contextlib
import io
import json
import os
import shlex
import stat
import subprocess
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

import firewall
import operations
from operations import OperationError

SECRET = 'synthetic-private-host-output'
BASELINE = [
    ('-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'),
    ('-A', 'INPUT', '-p', 'icmp', '-j', 'ACCEPT'),
    ('-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'),
    ('-A', 'INPUT', '-p', 'tcp', '-m', 'state', '--state', 'NEW', '-m', 'tcp', '--dport', '22', '-j', 'ACCEPT'),
    firewall.REJECT,
]
OTHER_CHAINS = (
    ':FORWARD DROP [13:1024]\n:OUTPUT ACCEPT [5:44]\n:DOCKER - [0:0]\n'
    '-A FORWARD -j DOCKER\n-A DOCKER -p tcp --dport 9999 -j ACCEPT\n'
    '-A OUTPUT -d 169.254.0.0/16 -j ACCEPT\n'
)


def persistence(rules):
    return (
        '# retained original comments\n*filter\n:INPUT ACCEPT [17:2345]\n' + OTHER_CHAINS
        + ''.join(shlex.join(rule) + '\n' for rule in rules) + 'COMMIT\n'
        '# unrelated Docker NAT must stay byte-identical\n*nat\n:PREROUTING ACCEPT [0:0]\n'
        ':POSTROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n-A PREROUTING -j DOCKER\nCOMMIT\n'
    ).encode()


class FirewallTests(unittest.TestCase):
    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='conspect-firewall-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'installation'
        self.root.mkdir(mode=0o750)
        self.rules_path = self.base / 'etc/iptables/rules.v4'
        self.rules_path.parent.mkdir(parents=True)
        self.rules_path.write_bytes(persistence(BASELINE))
        self.ufw_files = (self.base / 'etc/ufw/user.rules', self.base / 'etc/ufw/user6.rules')
        self.ufw_files[0].parent.mkdir()
        for path in self.ufw_files:
            path.write_bytes(b'# original private UFW configuration\n')
        self.programs = {'iptables', 'netfilter-persistent', 'systemctl'}
        self.rules = list(BASELINE)
        self.policy = 'ACCEPT'
        self.units = ''
        self.ufw_status = 'Status: inactive\n'
        self.nft = json.dumps({'nftables': [{'metainfo': {'version': '1.0'}}]})
        self.commands = []
        self.failures = {}
        self.owners = {}
        self.inserted = []
        self.ufw_allowed = set()
        self.output = self.enter(contextlib.redirect_stdout(io.StringIO()))
        self.enter(patch.object(firewall.platform, 'system', return_value='Linux'))
        self.enter(patch.object(firewall.os, 'geteuid', return_value=0))
        self.enter(patch.object(firewall, 'RULES_V4', self.rules_path))
        self.enter(patch.object(firewall, 'UFW_FILES', self.ufw_files))
        self.enter(patch.object(firewall.shutil, 'which', side_effect=lambda name: (
            '/usr/sbin/' + name if name in self.programs else None
        )))
        # Simulate root ownership without requiring root. All file modes/types and
        # symlinks below our private temporary directory remain real.
        real_stat = Path.stat
        external = set(self.base.parents)

        def owned_stat(path, *, follow_symlinks=True):
            info = list(real_stat(path, follow_symlinks=follow_symlinks))
            if path == self.base or self.base in path.parents:
                info[4] = self.owners.get(path, 0)
            elif path in external:
                info[4] = 0
                info[0] &= ~0o022
            return os.stat_result(info)

        self.enter(patch.object(Path, 'stat', owned_stat))
        self.enter(patch.object(subprocess, 'run', side_effect=AssertionError('Real subprocess forbidden')))
        self.enter(patch.object(operations, 'run_command', side_effect=AssertionError('Real command forbidden')))
        self.enter(patch.object(firewall, 'run_command', side_effect=self.command))

    def command(self, arguments, *, stdin, timeout):
        self.assertEqual(arguments[:2], ['env', 'LC_ALL=C'])
        self.assertEqual(stdin, subprocess.DEVNULL)
        self.assertEqual(timeout, 30)
        arguments = arguments[2:]
        self.commands.append(arguments)
        failure = self.failures.get(tuple(arguments))
        if failure is not None:
            raise failure
        if arguments[:2] == ['systemctl', 'list-units']:
            return self.units
        if arguments == ['ufw', 'status']:
            return self.ufw_status
        if arguments == ['nft', '--json', 'list', 'ruleset']:
            return self.nft
        if arguments == ['iptables', '-w', '10', '-S', 'INPUT']:
            return '-P INPUT ' + self.policy + '\n' + '\n'.join(shlex.join(rule) for rule in self.rules) + '\n'
        if arguments[:5] == ['iptables', '-w', '10', '-I', 'INPUT']:
            self.assert_backed_up()
            rule = ('-A', 'INPUT', *arguments[6:])
            self.rules.insert(int(arguments[5]) - 1, rule)
            self.inserted.append(rule)
            return ''
        if arguments[:2] == ['ufw', 'allow']:
            self.assert_backed_up()
            self.ufw_allowed.add(arguments[2])
            return 'Rules updated\n'
        raise AssertionError('Unexpected command: ' + repr(arguments))

    def assert_backed_up(self):
        directories = list((self.root / 'host').glob('firewall-backup-*'))
        self.assertTrue(directories)
        for directory in directories:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for path in directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertFalse(path.is_symlink())

    def mutations(self):
        return [args for args in self.commands if args[:2] == ['ufw', 'allow'] or '-I' in args]

    def assert_refused(self, callback=firewall.open_web_ports):
        before = self.rules_path.read_bytes()
        runtime = list(self.rules)
        with self.assertRaises(OperationError):
            callback(self.root)
        self.assertEqual(self.rules_path.read_bytes(), before)
        self.assertEqual(self.rules, runtime)
        self.assertEqual(self.mutations(), [])
        self.assertFalse((self.root / 'host').exists())

    def test_inspection_is_read_only_and_returns_none(self):
        before = self.rules_path.read_bytes()
        self.assertIsNone(firewall.inspect_firewall(self.root))
        self.assertEqual(self.rules_path.read_bytes(), before)
        self.assertFalse((self.root / 'host').exists())
        self.assertEqual(self.mutations(), [])
        self.assertIn('--open-web-ports', self.output.getvalue())
        self.assertIn('provider security groups', self.output.getvalue())

    def test_oracle_baseline_adds_only_web_before_terminal_reject(self):
        original = self.rules_path.read_bytes()
        self.assertIsNone(firewall.open_web_ports(self.root))
        self.assertEqual(self.rules, [*BASELINE[:-1], firewall.WEB_RULE, firewall.REJECT])
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertIn(['iptables', '-w', '10', '-I', 'INPUT', '5', *firewall.WEB_RULE[2:]], self.commands)
        self.assertEqual(self.rules_path.read_bytes(), original.replace(
            (shlex.join(firewall.REJECT) + '\n').encode(),
            (' '.join(firewall.WEB_RULE) + '\n' + shlex.join(firewall.REJECT) + '\n').encode(),
        ))
        backup = next((self.root / 'host').glob('firewall-backup-*'))
        self.assertEqual((backup / 'rules.v4').read_bytes(), original)
        self.assertEqual((backup / 'input.rules').read_text(), ''.join(shlex.join(rule) + '\n' for rule in BASELINE))
        self.assert_backed_up()
        self.assertEqual(stat.S_IMODE(self.rules_path.stat().st_mode), 0o600)
        self.assertTrue(all(args[0] in {'systemctl', 'iptables'} for args in self.commands))

    def test_other_table_input_and_whitespace_are_preserved(self):
        original = persistence(BASELINE).replace(b'-A INPUT ', b'  -A INPUT ')
        other = b'*mangle\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -j ACCEPT\nCOMMIT\n'
        self.rules_path.write_bytes(original + other)
        firewall.open_web_ports(self.root)
        updated = self.rules_path.read_bytes()
        addition = (' '.join(firewall.WEB_RULE) + '\n').encode()
        self.assertEqual(updated.replace(addition, b''), original + other)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])

    def test_complete_retry_makes_no_changes_or_extra_backups(self):
        firewall.open_web_ports(self.root)
        original = self.rules_path.read_bytes()
        backups = set((self.root / 'host').iterdir())
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertEqual(set((self.root / 'host').iterdir()), backups)

    def test_runtime_only_partial_retry_persists_without_duplicate_insert(self):
        self.rules.insert(-1, firewall.WEB_RULE)
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [])
        self.assertEqual(self.rules_path.read_bytes().count(firewall.COMMENT.encode()), 1)

    def test_persistence_only_partial_retry_adds_runtime_only(self):
        original = persistence([*BASELINE[:-1], firewall.WEB_RULE, firewall.REJECT])
        self.rules_path.write_bytes(original)
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertEqual(self.rules_path.read_bytes(), original)

    def test_active_ufw_uses_only_two_narrow_allows_and_backs_up_first(self):
        self.programs.update({'ufw', 'nft'})
        self.ufw_status = 'Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere\n'
        # UFW may itself own an iptables-nft ruleset; do not edit that backend.
        self.nft = json.dumps({'nftables': [{'table': {'family': 'ip', 'name': 'filter'}}]})
        original = self.rules_path.read_bytes()
        for _ in range(2):
            firewall.open_web_ports(self.root)
        self.assertEqual(self.ufw_allowed, {'80/tcp', '443/tcp'})
        self.assertEqual(self.mutations(), [['ufw', 'allow', port] for _ in range(2) for port in ('80/tcp', '443/tcp')])
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertFalse(any(args[0] in {'nft', 'iptables'} for args in self.commands))
        backup = next((self.root / 'host').glob('firewall-backup-*'))
        for path in self.ufw_files:
            self.assertEqual((backup / path.name).read_bytes(), path.read_bytes())
        self.assert_backed_up()

    def test_ufw_inspection_is_read_only(self):
        self.programs.add('ufw')
        self.ufw_status = 'Status: active\n'
        firewall.inspect_firewall(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertFalse((self.root / 'host').exists())

    def test_inactive_ufw_falls_back_without_enabling_it(self):
        self.programs.add('ufw')
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertFalse(any(args[:2] == ['ufw', 'allow'] for args in self.commands))

    def test_unknown_ufw_status_refuses_without_fallback(self):
        self.programs.add('ufw')
        self.ufw_status = SECRET
        self.assert_refused()
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_accept_without_deny_needs_no_changes_or_persistence(self):
        self.rules = [('-A', 'INPUT', '-s', '192.0.2.1/32', '-j', 'ACCEPT')]
        self.programs.discard('netfilter-persistent')
        self.rules_path.unlink()
        for callback in (firewall.inspect_firewall, firewall.open_web_ports):
            self.assertIsNone(callback(self.root))
        self.assertEqual(self.mutations(), [])
        self.assertFalse((self.root / 'host').exists())
        self.assertIn('no changes necessary', self.output.getvalue())

    def test_empty_accept_policy_needs_no_change(self):
        self.rules = []
        firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertFalse((self.root / 'host').exists())

    def test_missing_iptables_does_not_invent_or_install_firewall(self):
        self.programs.discard('iptables')
        for callback in (firewall.inspect_firewall, firewall.open_web_ports):
            self.assertIsNone(callback(self.root))
        self.assertEqual(self.mutations(), [])
        self.assertIn('No host firewall is known', self.output.getvalue())
        self.assertFalse((self.root / 'host').exists())

    def test_active_other_managers_refuse_even_with_ufw(self):
        self.programs.add('ufw')
        self.ufw_status = 'Status: active\n'
        for unit in ('nftables', 'firewalld'):
            with self.subTest(unit=unit):
                self.units = unit + '.service loaded active exited Firewall\n'
                self.assert_refused()

    def test_firewalld_without_service_inspection_refuses(self):
        self.programs.discard('systemctl')
        self.programs.add('firewall-cmd')
        self.assert_refused()

    def test_nonempty_or_malformed_nft_rulesets_refuse(self):
        self.programs.add('nft')
        for data in (SECRET, 'null', '{}', '{"nftables": null}', '{"nftables": [null]}',
                     '{"nftables": [{"table": {"family": "inet", "name": "firewall"}}]}'):
            with self.subTest(data=data):
                self.nft = data
                self.assert_refused()

    def test_empty_nft_ruleset_permits_iptables_fallback(self):
        self.programs.add('nft')
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])

    def test_unknown_or_complex_runtime_rules_refuse(self):
        variants = [
            [('-A', 'INPUT', '-j', 'DROP')],
            [('-A', 'INPUT', '-j', 'CUSTOM')],
            [('-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'DROP'), *BASELINE],
            [*BASELINE, ('-A', 'INPUT', '-j', 'ACCEPT')],
            [*BASELINE[:-1], ('-A', 'INPUT', '-j', 'REJECT')],
            [('-A', 'INPUT', '-s', '192.0.2.0/24', '-j', 'ACCEPT'), *BASELINE],
        ]
        for rules in variants:
            with self.subTest(rules=rules):
                self.rules = rules
                self.assert_refused()

    def test_drop_policy_refuses_even_with_matching_rules(self):
        self.policy = 'DROP'
        self.assert_refused()

    def test_changed_duplicate_or_misplaced_managed_comment_refuses(self):
        variants = [
            [*BASELINE[:-1], firewall.WEB_RULE, firewall.WEB_RULE, firewall.REJECT],
            [firewall.WEB_RULE, *BASELINE],
            [*BASELINE[:-1], tuple('81,443' if token == '80,443' else token for token in firewall.WEB_RULE), firewall.REJECT],
            [*BASELINE[:-1], firewall.WEB_RULE],
        ]
        for rules in variants:
            with self.subTest(rules=rules):
                self.rules = rules
                self.assert_refused()

    def test_missing_persistence_tool_refuses_before_runtime(self):
        self.programs.discard('netfilter-persistent')
        self.assert_refused()

    def test_persistence_layout_is_validated_even_during_read_only_preflight(self):
        for data in (b'*filter\n:INPUT DROP [0:0]\nCOMMIT\n', b'*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n',
                     persistence(BASELINE).replace(b'COMMIT\n', b'', 1),
                     persistence(BASELINE) + b'*filter\nCOMMIT\n', b'\xff' + persistence(BASELINE),
                     persistence([*BASELINE, ('-A', 'INPUT', '-j', 'DROP')]),
                     persistence([*BASELINE[:-1], firewall.WEB_RULE, firewall.WEB_RULE, firewall.REJECT])):
            with self.subTest(data=data):
                self.rules_path.write_bytes(data)
                self.assert_refused(firewall.inspect_firewall)
                self.assert_refused()

    def test_runtime_and_persistence_baseline_mismatch_refuses(self):
        self.rules_path.write_bytes(persistence(BASELINE[1:]))
        self.assert_refused()

    def test_conntrack_baseline_and_state_order_are_supported(self):
        self.rules = [tuple('conntrack' if token == 'state' else '--ctstate' if token == '--state'
                            else 'ESTABLISHED,RELATED' if token == 'RELATED,ESTABLISHED' else token
                            for token in rule) for rule in BASELINE]
        self.rules_path.write_bytes(persistence(self.rules))
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])

    def test_root_and_linux_are_required_for_both_apis(self):
        for callback in (firewall.inspect_firewall, firewall.open_web_ports):
            with patch.object(firewall.os, 'geteuid', return_value=1000):
                self.assert_refused(callback)
            with patch.object(firewall.platform, 'system', return_value='Windows'):
                self.assert_refused(callback)
        self.assertEqual(self.commands, [])

    def test_unsafe_roots_and_host_directory_refuse(self):
        for path in (self.root, self.root / 'host'):
            if not path.exists():
                path.mkdir()
            for mode in (0o777, 0o775):
                path.chmod(mode)
                with self.assertRaises(OperationError):
                    firewall.open_web_ports(self.root)
                self.assertEqual(self.mutations(), [])
            path.chmod(0o750)
            self.owners[path] = 1000
            with self.assertRaises(OperationError):
                firewall.inspect_firewall(self.root)
            self.owners[path] = 0
        with self.assertRaises(OperationError):
            firewall.open_web_ports(Path('relative-installation'))
        with self.assertRaises(OperationError):
            firewall.open_web_ports(self.root / '..' / self.root.name)

    def test_symlinked_root_and_host_refuse(self):
        link = self.base / 'linked-installation'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OperationError):
            firewall.open_web_ports(link)
        (self.root / 'host').symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OperationError):
            firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])

    def test_unsafe_persistence_ownership_mode_and_hardlinks_refuse(self):
        self.owners[self.rules_path] = 1000
        self.assert_refused()
        self.owners[self.rules_path] = 0
        self.rules_path.chmod(0o666)
        self.assert_refused()
        self.rules_path.chmod(0o644)
        os.link(self.rules_path, self.base / 'hardlink')
        self.assert_refused()

    def test_symlinked_persistence_file_or_parent_refuses(self):
        target = self.base / 'victim'
        original = self.rules_path.read_bytes()
        target.write_bytes(original)
        self.rules_path.unlink()
        self.rules_path.symlink_to(target)
        self.assert_refused()
        self.assertEqual(target.read_bytes(), original)
        self.rules_path.unlink()
        self.rules_path.parent.rmdir()
        self.rules_path.parent.symlink_to(self.ufw_files[0].parent, target_is_directory=True)
        (self.ufw_files[0].parent / 'rules.v4').write_bytes(original)
        self.assert_refused()

    def test_missing_persistence_file_is_sanitized_before_runtime(self):
        self.rules_path.unlink()
        with self.assertRaises(OperationError) as caught:
            firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertNotIn(str(self.base), str(caught.exception))
        self.assertFalse((self.root / 'host').exists())

    def test_ufw_requires_safe_both_config_files_before_any_allow(self):
        self.programs.add('ufw')
        self.ufw_status = 'Status: active\n'
        self.ufw_files[1].chmod(0o666)
        self.assert_refused()

    def test_command_failures_timeouts_and_decode_errors_are_secret_free(self):
        key = ('iptables', '-w', '10', '-S', 'INPUT')
        for failure in (OperationError(SECRET), OSError(SECRET),
                        subprocess.TimeoutExpired(SECRET, 30, output=SECRET, stderr=SECRET),
                        UnicodeError(SECRET)):
            with self.subTest(failure=type(failure)):
                self.failures[key] = failure
                try:
                    firewall.open_web_ports(self.root)
                except OperationError as error:
                    formatted = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
                    self.assertNotIn(SECRET, formatted)
                    self.assertFalse(hasattr(error, 'command_stderr'))
                else:
                    self.fail('Expected sanitized command error')
                self.assertEqual(self.mutations(), [])
                self.assertFalse((self.root / 'host').exists())

    def test_failed_backup_prevents_all_runtime_changes(self):
        with patch.object(firewall, '_backup', side_effect=OSError(SECRET)):
            with self.assertRaises(OperationError) as caught:
                firewall.open_web_ports(self.root)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.rules, BASELINE)

    def test_failed_temporary_preparation_prevents_runtime_change(self):
        with patch.object(firewall.tempfile, 'mkstemp', side_effect=OSError(SECRET)):
            with self.assertRaises(OperationError):
                firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.rules, BASELINE)
        self.assert_backed_up()

    def test_failed_insert_keeps_persistence_and_cleans_temporary_file(self):
        key = ('iptables', '-w', '10', '-I', 'INPUT', '5', *firewall.WEB_RULE[2:])
        self.failures[key] = OperationError(SECRET)
        original = self.rules_path.read_bytes()
        with self.assertRaises(OperationError):
            firewall.open_web_ports(self.root)
        self.assertEqual(self.rules, BASELINE)
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])

    def test_failed_persistence_is_narrow_and_retryable(self):
        original = self.rules_path.read_bytes()
        with patch.object(firewall.os, 'replace', side_effect=OSError(SECRET)):
            with self.assertRaises(OperationError) as caught:
                firewall.open_web_ports(self.root)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])
        firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertEqual(self.rules_path.read_bytes().count(firewall.COMMENT.encode()), 1)

    def test_failed_second_ufw_allow_is_retryable_without_reset_or_reload(self):
        self.programs.add('ufw')
        self.ufw_status = 'Status: active\n'
        key = ('ufw', 'allow', '443/tcp')
        self.failures[key] = OperationError(SECRET)
        with self.assertRaises(OperationError):
            firewall.open_web_ports(self.root)
        self.assertEqual(self.ufw_allowed, {'80/tcp'})
        self.failures.clear()
        firewall.open_web_ports(self.root)
        self.assertEqual(self.ufw_allowed, {'80/tcp', '443/tcp'})
        self.assertTrue(all(args[1] in {'status', 'allow'} for args in self.commands if args[0] == 'ufw'))

    def test_concurrent_persistence_change_refuses_before_runtime_mutation(self):
        real_backup = firewall._backup

        def change(host, files):
            real_backup(host, files)
            self.rules_path.write_bytes(persistence(BASELINE) + b'# concurrent edit\n')

        with patch.object(firewall, '_backup', side_effect=change):
            with self.assertRaises(OperationError):
                firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertTrue(self.rules_path.read_bytes().endswith(b'# concurrent edit\n'))
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])

    def test_concurrent_runtime_change_prevents_insert_and_persistence(self):
        real_backup = firewall._backup
        original = self.rules_path.read_bytes()

        def change(host, files):
            real_backup(host, files)
            self.rules.insert(0, ('-A', 'INPUT', '-j', 'DROP'))

        with patch.object(firewall, '_backup', side_effect=change):
            with self.assertRaises(OperationError):
                firewall.open_web_ports(self.root)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])

    def test_concurrent_persistence_edit_after_insert_is_not_overwritten(self):
        real_command = self.command
        original = self.rules_path.read_bytes()

        def change(arguments, **kwargs):
            output = real_command(arguments, **kwargs)
            if '-I' in arguments:
                self.rules_path.write_bytes(original + b'# concurrent edit\n')
            return output

        with patch.object(firewall, 'run_command', side_effect=change):
            with self.assertRaises(OperationError):
                firewall.open_web_ports(self.root)
        self.assertEqual(self.inserted, [firewall.WEB_RULE])
        self.assertEqual(self.rules_path.read_bytes(), original + b'# concurrent edit\n')
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])

    def test_missing_runtime_addition_is_not_persisted(self):
        real_command = self.command
        original = self.rules_path.read_bytes()

        def disappear(arguments, **kwargs):
            output = real_command(arguments, **kwargs)
            if '-I' in arguments:
                self.rules.remove(firewall.WEB_RULE)
            return output

        with patch.object(firewall, 'run_command', side_effect=disappear):
            with self.assertRaises(OperationError):
                firewall.open_web_ports(self.root)
        self.assertEqual(self.rules, BASELINE)
        self.assertEqual(self.rules_path.read_bytes(), original)
        self.assertEqual(list(self.rules_path.parent.glob('.conspect-firewall-*')), [])


if __name__ == '__main__':
    unittest.main()
