#!/usr/bin/python3
"""Bounded, isolated storage-prompt regression; never starts a VM.

Run with /usr/bin/python3 tests/validate_prompt.py. Raw subprocess logs and
results.json are retained in a new tests/p-* directory on every invocation.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time

TESTS = Path(__file__).resolve().parent
BINARY = TESTS.parent / 'output' / 'limactl'
PROMPT = b'Lima storage directory [~/goinfre/lima-home]: '
PROCESS_LIMIT = 8.0
SUITE_LIMIT = 110.0
SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'


def foreground_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.tcsetpgrp(0, os.getpgrp())


def snapshot(home):
    result = {}
    for path in sorted(home.rglob('*')):
        info = path.lstat()
        value = {'mode': stat.S_IMODE(info.st_mode)}
        if path.is_symlink():
            value['link'] = os.readlink(path)
        elif path.is_file():
            value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            value['directory'] = True
        result[str(path.relative_to(home))] = value
    return result


def run_child(root, spec, suite_deadline):
    started = time.monotonic()
    # Reserve half a second inside the eight-second bound for teardown.
    deadline = min(started + PROCESS_LIMIT - 0.5, suite_deadline - 0.5)
    home = root / spec['home'] / 'h'
    tmp = root / spec['home'] / 't'
    env = {
        'HOME': str(home), 'TMPDIR': str(tmp), 'PATH': SYSTEM_PATH,
        'LANG': 'C', 'LC_ALL': 'C', 'TERM': 'dumb',
        'USER': 'prompt-test', 'LOGNAME': 'prompt-test',
        'XDG_CONFIG_HOME': str(home / '.config'),
        'XDG_CACHE_HOME': str(home / '.cache'),
        'XDG_DATA_HOME': str(home / '.local' / 'share'),
    }
    if 'override' in spec:
        env['LIMA_HOME'] = str(spec['override'])
    command = [str(BINARY)] + spec.get('args', ['list'])
    record = {
        'name': spec['name'], 'argv': command, 'env': env,
        'interactive': spec.get('interactive', True),
        'input': spec.get('answer', spec.get('pipe', '')),
        'log': spec['name'] + '.log', 'timed_out': False,
    }
    process = None
    master = slave = None
    output = bytearray()
    sent = False
    selector = selectors.DefaultSelector()
    try:
        with (root / record['log']).open('wb', buffering=0) as log:
            if record['interactive']:
                master, slave = pty.openpty()
                process = subprocess.Popen(
                    command, stdin=slave, stdout=slave, stderr=slave,
                    cwd=home, env=env, close_fds=True,
                    preexec_fn=foreground_terminal,
                )
                os.close(slave)
                slave = None
                fd = master
            else:
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, cwd=home, env=env,
                    close_fds=True, start_new_session=True,
                )
                try:
                    process.stdin.write(spec.get('pipe', '').encode())
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
                finally:
                    process.stdin.close()
                fd = process.stdout.fileno()
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ)
            eof = False
            while not (eof and process.poll() is not None):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record['timed_out'] = True
                    break
                events = selector.select(min(0.05, remaining))
                for key, _ in events:
                    try:
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        if exc.errno != errno.EIO or not record['interactive']:
                            raise
                        data = b''
                    if not data:
                        selector.unregister(key.fd)
                        eof = True
                        continue
                    output.extend(data)
                    log.write(data)
                    if (record['interactive'] and not sent
                            and 'answer' in spec and PROMPT in output):
                        os.write(master, spec['answer'].encode())
                        sent = True
    finally:
        if process is not None:
            # Also remove any descendants after the direct child has exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=0.4)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
        selector.close()
        for fd in (master, slave):
            if fd is not None:
                os.close(fd)
        record['returncode'] = process.returncode if process else None
        record['elapsed_seconds'] = round(time.monotonic() - started, 4)
        record['answer_sent'] = sent
        record['prompt_count'] = output.count(PROMPT)
        record['output'] = output.decode('utf-8', errors='backslashreplace')
        # Preserve partial metadata even if a suite deadline interrupts this case.
        (root / (spec['name'] + '.json')).write_text(
            json.dumps(record, indent=2) + '\n')
    return record


def main():
    started = time.monotonic()
    root = Path(tempfile.mkdtemp(prefix='p-', dir=TESTS))
    os.chmod(root, 0o700)
    results = {
        'binary': str(BINARY), 'results_directory': str(root),
        'expected_prompt': PROMPT.decode(), 'process_limit_seconds': PROCESS_LIMIT,
        'suite_limit_seconds': SUITE_LIMIT, 'cases': [],
    }
    print('RESULTS: ' + str(root), flush=True)
    print('EXACT PROMPT: ' + repr(PROMPT.decode()), flush=True)

    def expired(signum, frame):
        raise TimeoutError('110-second overall regression deadline exceeded')

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, SUITE_LIMIT)
    try:
        tags = ('d', 'a', 't', 'e', 'x', 'n', 'p', 'hf', 'hc', 'vf', 'c')
        for tag in tags:
            (root / tag / 'h').mkdir(parents=True, mode=0o700)
            (root / tag / 't').mkdir(mode=0o700)
        default = root / 'd/h/goinfre/lima-home'
        absolute = root / 'a/s'
        tilde = root / 't/h/storage'
        override = root / 'e/s'
        poison = root / 'x/h/goinfre/lima-config.json'
        poison.parent.mkdir(mode=0o700)
        poison.write_text('{invalid saved JSON\n')
        poison.chmod(0o600)
        specs = [
            dict(name='01-enter-default', home='d', answer='\n', choice=default),
            dict(name='02-saved-default', home='d', choice=default, unchanged=True),
            dict(name='03-custom-absolute', home='a', answer=str(absolute) + '\n', choice=absolute),
            dict(name='04-saved-absolute', home='a', choice=absolute, unchanged=True),
            dict(name='05-custom-tilde', home='t', answer='~/storage\n', choice=tilde),
            dict(name='06-saved-tilde', home='t', choice=tilde, unchanged=True),
            dict(name='07-override-clean', home='e', override=override, unchanged=True, no_config=True),
            dict(name='08-override-saved', home='a', override=override, choice=absolute, unchanged=True),
            dict(name='09-override-invalid-config', home='x', override=override, unchanged=True),
            dict(name='10-noninteractive-eof', home='n', interactive=False, no_config=True),
            dict(name='11-noninteractive-piped-choice', home='p', interactive=False,
                 pipe=str(root / 'p/unconfirmed') + '\n', no_config=True),
            dict(name='12-help-flag', home='hf', args=['--help'], unchanged=True, no_config=True),
            dict(name='13-help-command', home='hc', args=['help'], unchanged=True, no_config=True),
            dict(name='14-version-flag', home='vf', args=['--version'], unchanged=True, no_config=True),
            dict(name='15-completion', home='c', args=['completion', 'bash'], unchanged=True, no_config=True),
        ]
        for spec in specs:
            home = root / spec['home'] / 'h'
            config = home / 'goinfre/lima-config.json'
            before = snapshot(home)
            record = run_child(root, spec, started + SUITE_LIMIT)
            checks = {
                'exited_successfully': record['returncode'] == 0,
                'within_process_bound': not record['timed_out'] and record['elapsed_seconds'] <= PROCESS_LIMIT,
                'expected_prompt_count': record['prompt_count'] == (1 if 'answer' in spec else 0),
            }
            if 'answer' in spec:
                checks['answer_sent_after_prompt'] = record['answer_sent']
                checks['saved_confirmation'] = ('Lima storage directory saved: ' + str(spec['choice'])) in record['output']
            else:
                checks['no_storage_prompt_or_save_message'] = 'Lima storage directory' not in record['output']
            if 'choice' in spec:
                try:
                    checks['persisted_absolute_choice'] = json.loads(config.read_text()) == {'home': str(spec['choice'])}
                    checks['config_mode_0600'] = stat.S_IMODE(config.stat().st_mode) == 0o600
                    checks['chosen_directory_exists'] = spec['choice'].is_dir()
                except (OSError, ValueError) as exc:
                    checks['valid_persisted_config'] = False
                    record['config_error'] = str(exc)
            if spec.get('unchanged'):
                checks['home_untouched'] = before == snapshot(home)
            if spec.get('no_config'):
                checks['no_unconfirmed_persistence'] = not config.exists()
            if not spec.get('interactive', True):
                checks['piped_choice_not_created'] = not (root / 'p/unconfirmed').exists()
            if 'args' in spec:
                checks['command_produced_output'] = bool(record['output'].strip())
            record['checks'] = checks
            record['passed'] = all(checks.values())
            results['cases'].append(record)
            (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            failed = [key for key, value in checks.items() if not value]
            print(('PASS' if record['passed'] else 'FAIL') + ' ' + spec['name']
                  + ' (' + str(record['elapsed_seconds']) + 's)'
                  + (': ' + ', '.join(failed) if failed else ''), flush=True)
            if 'answer' in spec or not record['passed']:
                print('  exact terminal output: ' + repr(record['output']), flush=True)
        results['passed'] = all(case['passed'] for case in results['cases'])
    except Exception as exc:
        results['passed'] = False
        results['error'] = type(exc).__name__ + ': ' + str(exc)
        print('FAIL ' + results['error'], flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        results['elapsed_seconds'] = round(time.monotonic() - started, 4)
        results['passed_count'] = sum(case['passed'] for case in results['cases'])
        results['completed_count'] = len(results['cases'])
        (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print('SUMMARY: ' + str(results['passed_count']) + '/' + str(results['completed_count'])
              + ' passed; ' + str(results['elapsed_seconds']) + 's; '
              + ('PASS' if results.get('passed') else 'FAIL'), flush=True)
    return 0 if results.get('passed') else 1


if __name__ == '__main__':
    sys.exit(main())
