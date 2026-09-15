#!/usr/bin/env python3
"""Bounded, offline validation of the final single-file executable.

Run with python3 -B tests/validate_native.py from the repository root.
Only the script and native-validation-* fixtures/logs in this directory are written.
No wrapper workers, signing, process queries, process groups, or build changes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / 'tests'
BINARY = ROOT / 'output' / 'limactl'
RESOURCE_MANIFEST = ROOT / 'src/qemu/util/builtin-resources/manifest.json'
FIRMWARE_NAME = 'edk2-x86_64-code.fd'
BUILTIN = 'builtin:' + FIRMWARE_NAME
CASE_SECONDS = 25
OVERALL_SECONDS = 240
UNSAFE = re.compile(r'Assertion failed|assertion\s+.*?failed|assertion failure|Bail out!|'
                    r'fatal error:|SIGSEGV|SIGBUS|SIGABRT|Segmentation fault|'
                    r'Bus error|unexpected signal during runtime execution', re.I)


class Failure(Exception):
    pass


class Unsafe(Failure):
    pass


class EnvironmentDenied(Failure):
    pass


class OverallTimeout(BaseException):
    pass


def require(ok, message):
    if not ok:
        raise Failure(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_firmware_spec(path=RESOURCE_MANIFEST):
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise Failure('Cannot read embedded resource manifest %s: %s' % (path, exc)) from exc
    require(isinstance(manifest, dict) and manifest.get('format') == 1,
            'unsupported embedded resource manifest format')
    resources = manifest.get('resources')
    require(isinstance(resources, list), 'embedded resource manifest has no resource list')
    matches = [entry for entry in resources
               if isinstance(entry, dict) and entry.get('name') == FIRMWARE_NAME]
    require(len(matches) == 1, 'embedded resource manifest must identify exactly one ' + FIRMWARE_NAME)
    entry = matches[0]
    require(type(entry.get('size')) is int and entry['size'] > 0,
            'invalid embedded firmware size in manifest')
    require(isinstance(entry.get('sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', entry['sha256']),
            'invalid embedded firmware SHA-256 in manifest')
    return {key: entry[key] for key in ('name', 'size', 'sha256')}


def discover_otool():
    xcrun = shutil.which('xcrun')
    require(xcrun is not None, 'xcrun is required to locate otool; install/select Apple developer tools')
    try:
        result = subprocess.run([xcrun, '--find', 'otool'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Failure('Cannot locate otool through xcrun: %s' % exc) from exc
    tool = Path(result.stdout.strip())
    require(tool.is_absolute() and tool.is_file() and os.access(tool, os.X_OK),
            'xcrun returned an unusable otool path: ' + result.stdout.strip())
    return str(tool)


def verify_firmware(path, spec):
    actual = digest(path)
    require(path.stat().st_size == spec['size'] and actual == spec['sha256'],
            'embedded firmware content/size differs from manifest: ' + str(path))
    return actual


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


class Owned:
    """Reap exactly the Popen child we own; persist output even on failure."""
    def __init__(self, suite, args, qmp=False, executable=None):
        self.suite = suite
        self.index = len(suite.current['commands']) + 1
        self.base = suite.case_dir / ('%02d' % self.index)
        self.stdout_path = self.base.with_suffix('.stdout.log')
        self.stderr_path = self.base.with_suffix('.stderr.log')
        self.out = self.stdout_path.open('wb', buffering=0)
        self.err = self.stderr_path.open('wb', buffering=0)
        self.qmp = qmp
        self.buffer = b''
        self.events = []
        self.eof = False
        self.seq = 0
        self.closed = False
        self.meta = {'argv': [str(executable or suite.binary)] + list(map(str, args)),
                     'cwd': str(suite.runtime), 'environment': suite.env,
                     'stdout': str(self.stdout_path), 'stderr': str(self.stderr_path),
                     'status': 'starting', 'returncode': None,
                     'timeout_seconds': CASE_SECONDS, 'qmp_requests': []}
        suite.current['commands'].append(self.meta)
        suite.save()
        self.started = time.monotonic()
        self.deadline = min(suite.case_deadline, suite.deadline)
        try:
            self.p = subprocess.Popen(self.meta['argv'], cwd=suite.runtime, env=suite.env,
                                      stdin=subprocess.PIPE if qmp else subprocess.DEVNULL,
                                      stdout=subprocess.PIPE if qmp else self.out, stderr=self.err,
                                      start_new_session=True, close_fds=True)
        except BaseException:
            self.out.close()
            self.err.close()
            self.meta['status'] = 'spawn_failed'
            suite.save()
            raise
        suite.owned.append(self)
        self.meta.update(pid=self.p.pid, status='running')
        if qmp:
            os.set_blocking(self.p.stdout.fileno(), False)
            os.set_blocking(self.p.stdin.fileno(), False)
        suite.save()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        self.close()
        return False

    def left(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            self.meta['status'] = 'timed_out'
            raise Failure('25s case/overall deadline reached: ' + repr(self.meta['argv']))
        return value

    def text(self):
        return self.stdout_path.read_text(errors='replace') + self.stderr_path.read_text(errors='replace')

    def safety(self):
        text = self.text()
        match = UNSAFE.search(text)
        rc = self.p.poll()
        if match or rc in (-signal.SIGABRT, -signal.SIGSEGV, -signal.SIGBUS, -signal.SIGILL):
            self.meta['unsafe_runtime'] = True
            detail = text[max(0, match.start()-100):match.start()+1800] if match else text[-1800:]
            raise Unsafe('unsafe native runtime, exit=%s: %s' % (rc, detail))

    def read_some(self):
        ready, _, _ = select.select([self.p.stdout], [], [], min(self.left(), 0.2))
        if ready:
            chunk = os.read(self.p.stdout.fileno(), 65536)
            if not chunk:
                self.eof = True
            else:
                self.out.write(chunk)
                self.buffer += chunk
                require(len(self.buffer) < 8 * 1024 * 1024, 'oversized QMP pending data')
        self.safety()

    def message(self):
        while b'\n' not in self.buffer:
            require(not self.eof, 'QMP EOF, exit=%s: %s' % (self.p.poll(), self.text()[-2200:]))
            self.read_some()
        line, self.buffer = self.buffer.split(b'\n', 1)
        try:
            msg = json.loads(line)
        except ValueError as exc:
            raise Failure('non-JSON QMP stdout: ' + repr(line)) from exc
        if 'event' in msg:
            self.events.append(msg)
        return msg

    def handshake(self):
        hello = self.message()
        require('QMP' in hello, 'missing QMP greeting: ' + repr(hello))
        self.command('qmp_capabilities')

    def command(self, name, arguments=None):
        self.seq += 1
        request = {'execute': name, 'id': self.seq}
        if arguments is not None:
            request['arguments'] = arguments
        self.meta['qmp_requests'].append(request)
        self.suite.save()
        data = (json.dumps(request) + '\n').encode()
        while data:
            _, ready, _ = select.select([], [self.p.stdin], [], self.left())
            require(ready, 'QMP send timeout')
            count = os.write(self.p.stdin.fileno(), data)
            require(count > 0, 'QMP send made no progress')
            data = data[count:]
        while True:
            msg = self.message()
            if msg.get('id') == self.seq:
                require('error' not in msg, 'QMP %s failed: %r' % (name, msg))
                require('return' in msg, 'QMP response missing return')
                return msg['return']

    def status(self, running):
        result = self.command('query-status')
        require(result['running'] is running, 'unexpected VM state: ' + repr(result))

    def wait(self, expected=0):
        try:
            if self.qmp:
                while not self.eof:
                    self.read_some()
                # Keep shutdown events even when waiting after a signal/quit.
                while b'\n' in self.buffer:
                    self.message()
            rc = self.p.wait(timeout=self.left())
        except subprocess.TimeoutExpired as exc:
            self.meta['status'] = 'timed_out'
            raise Failure('process timeout: ' + repr(self.meta['argv'])) from exc
        self.meta.update(returncode=rc, status='exited')
        self.safety()
        if expected is not None:
            require(rc == expected, 'exit %s, expected %s: %s' % (rc, expected, self.text()[-2500:]))
        return rc

    def close(self):
        if self.closed:
            return
        try:
            if self.p.poll() is None:
                self.meta['cleanup'] = 'direct terminate then kill if needed'
                self.p.terminate()
                try:
                    self.p.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.p.kill()
                    self.p.wait(timeout=2)
            if self.qmp:
                # Child is reaped: drain finite output without a blocking pipe read.
                while True:
                    chunk = os.read(self.p.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    self.out.write(chunk)
                self.p.stdout.close()
                self.p.stdin.close()
            self.meta['returncode'] = self.p.returncode
            self.meta['seconds'] = round(time.monotonic() - self.started, 3)
            self.meta['qmp_events'] = self.events
            if self.meta['status'] == 'running':
                self.meta['status'] = 'cleaned_up'
        finally:
            self.out.close()
            self.err.close()
            self.closed = True
            self.suite.save()
        self.safety()


class Suite:
    def __init__(self):
        self.started = time.monotonic()
        self.deadline = self.started + OVERALL_SECONDS - 5
        require(BINARY.is_file(), 'missing single-file executable: ' + str(BINARY))
        self.firmware = load_firmware_spec()
        self.otool = discover_otool()
        self.root = Path(tempfile.mkdtemp(prefix='native-validation-', dir=TESTS))
        self.runtime, self.home, self.tmp, self.cache, self.fixtures, self.logs = [
            self.root / name for name in ('standalone', 'home', 'tmp', 'cache', 'fixtures', 'logs')]
        for directory in (self.runtime, self.home, self.tmp, self.cache, self.fixtures, self.logs):
            directory.mkdir()
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(self.home),
                    'TMPDIR': str(self.tmp), 'TMP': str(self.tmp), 'TEMP': str(self.tmp),
                    'XDG_CACHE_HOME': str(self.cache), 'GOCACHE': str(self.cache / 'go-build'),
                    'GOMODCACHE': str(self.cache / 'go-mod'), 'LC_ALL': 'C',
                    'PYTHONDONTWRITEBYTECODE': '1'}
        os.environ.clear()
        os.environ.update(self.env)
        self.binary = self.runtime / 'limactl'
        self.owned = []
        self.current = None
        self.result = {'status': 'partial', 'complete': False, 'source': str(BINARY),
                       'firmware': {'manifest': str(RESOURCE_MANIFEST), **self.firmware},
                       'otool': self.otool,
                       'root': str(self.root), 'environment': self.env,
                       'overall_timeout_seconds': OVERALL_SECONDS,
                       'case_timeout_seconds': CASE_SECONDS, 'tests': []}
        self.save()
        shutil.copy2(BINARY, self.binary)
        self.result['executable'] = {'path': str(self.binary), 'bytes': self.binary.stat().st_size,
                                     'sha256': digest(self.binary), 'source_sha256': digest(BINARY)}
        require(self.result['executable']['sha256'] == self.result['executable']['source_sha256'],
                'relocated binary hash mismatch')
        self.config = self.home / 'goinfre' / 'lima-config.json'
        self.config.parent.mkdir()
        self.save()

    def save(self):
        self.result['elapsed_seconds'] = round(time.monotonic() - self.started, 3)
        write_json(self.root / 'results.json', self.result)

    def run(self, args, expected=0, executable=None):
        with Owned(self, args, executable=executable) as child:
            rc = child.wait(expected)
        return rc, child.stdout_path.read_text(errors='replace'), child.stderr_path.read_text(errors='replace')

    def img(self, *args, expected=0):
        return self.run(['--internal-qemu-img', *map(str, args)], expected=expected)

    def info(self, path, fmt):
        _, out, _ = self.img('info', '--output=json', '-f', fmt, path)
        data = json.loads(out)
        require(data['format'] == fmt, 'incorrect disk format: ' + repr(data))
        self.current.setdefault('image_info', []).append(data)
        return data

    def versions(self):
        for flag, prefix in (('--internal-qemu-img', 'qemu-img version 10.0.2'),
                             ('--internal-qemu', 'QEMU emulator version 10.0.2')):
            _, out, _ = self.run([flag, '--version'])
            require(out.startswith(prefix), 'unexpected worker version: ' + out)

    def early_image(self):
        path = self.fixtures / 'early.qcow2'
        self.img('create', '-f', 'qcow2', path, '2M')
        data = self.info(path, 'qcow2')
        require(data['virtual-size'] == 2 * 1024 * 1024, 'create virtual-size mismatch')
        require(0 < data['actual-size'] <= data['virtual-size'], 'invalid create allocated size')
        require(data['actual-size'] == path.stat().st_blocks * 512, 'allocated disk size disagrees with stat')

    def cli(self, args, corrupt):
        bad = '{ deliberately invalid json\n'
        if corrupt:
            self.config.write_text(bad)
        else:
            self.config.unlink(missing_ok=True)
        _, out, _ = self.run(args)
        require(bool(out.strip()), 'empty CLI output for ' + repr(args))
        if args == ['--help']:
            require('Usage:' in out and 'limactl' in out and 'licenses' in out, 'invalid CLI help')
        elif args == ['--version']:
            require('limactl' in out.lower() and re.search(r'\d+\.\d+', out), 'invalid Lima version')
        elif args == ['start', '--list-templates']:
            require('default' in out and 'ubuntu' in out, 'missing embedded default/ubuntu templates')
        else:
            require(re.search(r'license|copyright', out, re.I), 'missing embedded license text')
        if corrupt:
            require(self.config.read_text() == bad, 'CLI modified corrupt config')

    def images(self):
        size = 2 * 1024 * 1024
        raw, qcow, back, grown = [self.fixtures / name for name in
                                   ('content.raw', 'content.qcow2', 'roundtrip.raw', 'grown.raw')]
        self.img('create', '-f', 'raw', raw, str(size))
        require(raw.stat().st_size == size, 'raw create disk size mismatch')
        expected = bytes(range(256)) * (size // 256)
        with raw.open('r+b') as stream:
            stream.write(expected)
        self.img('convert', '-f', 'raw', '-O', 'qcow2', raw, qcow)
        data = self.info(qcow, 'qcow2')
        require(data['virtual-size'] == size, 'convert virtual size mismatch')
        require(data['actual-size'] == qcow.stat().st_blocks * 512, 'convert allocated size mismatch')
        self.img('convert', '-f', 'qcow2', '-O', 'raw', qcow, back)
        require(back.stat().st_size == size and back.read_bytes() == expected, 'roundtrip data/size mismatch')
        self.img('resize', '-f', 'qcow2', qcow, '+1M')
        data = self.info(qcow, 'qcow2')
        require(data['virtual-size'] == size + 1024 * 1024, 'resize virtual size mismatch')
        self.img('convert', '-f', 'qcow2', '-O', 'raw', qcow, grown)
        require(grown.stat().st_size == size + 1024 * 1024, 'resized raw disk size mismatch')
        require(grown.read_bytes() == expected + bytes(1024 * 1024), 'resize content/zero extension mismatch')
        _, out, _ = self.img('check', '--output=json', '-f', 'qcow2', qcow)
        checked = json.loads(out)
        require(checked.get('check-errors') == 0, 'check errors: ' + repr(checked))
        require(checked.get('corruptions', 0) == 0 and checked.get('leaks', 0) == 0,
                'check corruption/leaks: ' + repr(checked))
        self.current['check'] = checked
        self.current['content_sha256'] = digest(back)

    def builtin_read(self):
        data = self.info(BUILTIN, 'raw')
        require(data['virtual-size'] == self.firmware['size'], 'builtin firmware virtual size mismatch')
        target = self.fixtures / 'embedded-edk2.fd'
        self.img('convert', '-f', 'raw', '-O', 'raw', BUILTIN, target)
        actual = verify_firmware(target, self.firmware)
        self.current['firmware'] = {'manifest': str(RESOURCE_MANIFEST), 'resource': FIRMWARE_NAME,
                                    'bytes': target.stat().st_size, 'sha256': actual,
                                    'expected_sha256': self.firmware['sha256']}

    def builtin_rejections(self):
        rc, out, err = self.img('info', '-f', 'raw', 'builtin:__native_validation_missing__.fd', expected=None)
        require(rc > 0 and re.search(r'not found|no such|unknown|missing|does not exist', out + err, re.I),
                'missing builtin did not return a descriptive error: ' + out + err)
        rc, out, err = self.img('resize', '-f', 'raw', BUILTIN, '+64K', expected=None)
        require(rc > 0 and re.search(r'read.only|readonly|writ|permission|not permitted', out + err, re.I),
                'builtin readonly resize was not rejected descriptively: ' + out + err)
        target = self.fixtures / 'embedded-after-rejection.fd'
        self.img('convert', '-f', 'raw', '-O', 'raw', BUILTIN, target)
        actual = verify_firmware(target, self.firmware)
        self.current['firmware_after_rejection'] = {'bytes': target.stat().st_size,
                                                   'sha256': actual,
                                                   'expected_sha256': self.firmware['sha256']}

    def machine(self, accel='tcg', uefi=False, network=False):
        args = ['--internal-qemu', '-machine', ('q35' if uefi else 'pc') + ',accel=' + accel,
                '-m', '128M', '-nodefaults', '-display', 'none', '-monitor', 'none',
                '-serial', 'none', '-parallel', 'none', '-nic', 'none', '-no-reboot']
        if uefi:
            args += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + BUILTIN]
        if network:
            args += ['-netdev', 'user,id=net0', '-device', 'e1000,netdev=net0,id=nic0']
        return args

    def lifecycle(self, uefi=False, network=False, accel='tcg', sig=None):
        child = None
        try:
            with Owned(self, self.machine(accel, uefi, network) + ['-S', '-qmp', 'stdio'], qmp=True) as child:
                child.handshake()
                child.status(False)
                if uefi:
                    blocks = child.command('query-block')
                    require(any(b.get('inserted', {}).get('ro') is True and
                                BUILTIN in json.dumps(b) for b in blocks),
                            'builtin readonly pflash not visible in query-block: ' + repr(blocks))
                if network:
                    pci = child.command('query-pci')
                    require('nic0' in json.dumps(pci), 'user networking PCI device missing')
                    usernet = child.command('human-monitor-command', {'command-line': 'info usernet'})
                    require('net0' in usernet, 'slirp user backend missing: ' + usernet)
                child.command('cont')
                time.sleep(0.4)
                child.status(True)
                if sig is not None:
                    child.meta['signal_sent'] = signal.Signals(sig).name
                    self.save()
                    child.p.send_signal(sig)
                else:
                    child.command('stop')
                    child.status(False)
                    child.command('cont')
                    child.status(True)
                    child.command('stop')
                    child.status(False)
                    child.command('quit')
                child.wait(0)
                events = [event['event'] for event in child.events]
                require('SHUTDOWN' in events, 'missing QMP SHUTDOWN event')
                if sig is None:
                    require(events.count('RESUME') == 2 and events.count('STOP') == 2,
                            'missing QMP lifecycle events: ' + repr(events))
        except Unsafe:
            raise
        except Exception as exc:
            text = child.text() if child is not None else ''
            if accel == 'hvf' and re.search(r'HV_DENIED|HV_NO_DEVICE|HV_UNSUPPORTED|entitlement|'
                                          r'operation not permitted|permission denied|not supported|'
                                          r'0xfae94007', text, re.I):
                raise EnvironmentDenied('HVF unavailable/denied (NOT a pass): ' + text[-2500:]) from exc
            raise

    def tiny_rom(self):
        # Reuse only the reset-vector bytes from go-bridge/tests/test_bridge.py
        # Suite.__init__/guest_exit, not its wrapper/process-discovery harness.
        firmware = bytearray([0xff]) * 65536
        firmware[-16:-9] = bytes.fromhex('b0 2a e6 f4 f4 eb fd')
        rom = self.fixtures / 'exit-test.rom'
        rom.write_bytes(firmware)
        _, out, _ = self.run(self.machine() + ['-bios', str(rom), '-device',
                                              'isa-debug-exit,iobase=0xf4,iosize=0x04'], expected=85)
        require(not out, 'unexpected tiny-ROM stdout')
        self.current['rom_sha256'] = digest(rom)
        self.current['expected_exit'] = 85

    def dependencies(self):
        _, out, _ = self.run(['-L', self.binary], executable=self.otool)
        dependencies = []
        for line in out.splitlines():
            if ' (compatibility version ' in line:
                dependencies.append(line.strip().split(' (compatibility version ', 1)[0])
        require(dependencies, 'otool returned no parsed dependencies')
        self.current['dependencies'] = dependencies
        forbidden = [name for name in dependencies if not name.startswith(
            ('/usr/lib/', '/System/Library/'))]
        require(not forbidden, 'non-system dylib dependencies: ' + repr(forbidden))

    def isolation(self):
        require(list(self.runtime.iterdir()) == [self.binary], 'standalone directory gained sidecar assets')
        forbidden = [str(p) for root in (self.home, self.tmp, self.cache) for p in root.rglob('*')
                     if p.suffix in ('.dylib', '.so', '.a')]
        require(not forbidden, 'native library extraction: ' + repr(forbidden))
        require(digest(self.binary) == self.result['executable']['sha256'], 'relocated executable was modified')

    def execute(self):
        cases = [('worker-versions', self.versions), ('native-image-create-info-early', self.early_image)]
        for corrupt in (False, True):
            for name, args in (('help', ['--help']), ('version', ['--version']),
                               ('templates', ['start', '--list-templates']), ('licenses', ['licenses'])):
                cases.append(('cli-' + name + ('-corrupt-config' if corrupt else '-clean-config'),
                              lambda args=args, corrupt=corrupt: self.cli(args, corrupt)))
        cases += [('image-content-convert-resize-check', self.images),
                  ('builtin-firmware-info-read-hash', self.builtin_read),
                  ('builtin-missing-and-readonly-rejection', self.builtin_rejections),
                  ('tcg-default-bios-qmp', self.lifecycle),
                  ('tcg-builtin-uefi-pflash-qmp', lambda: self.lifecycle(uefi=True)),
                  ('tcg-user-network-device-qmp', lambda: self.lifecycle(network=True)),
                  ('tcg-tiny-rom-exit85', self.tiny_rom)]
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            cases.append(('direct-worker-' + signal.Signals(sig).name,
                          lambda sig=sig: self.lifecycle(sig=sig)))
        cases += [('system-dylib-audit', self.dependencies),
                  ('hvf-qmp-probe', lambda: self.lifecycle(accel='hvf')),
                  ('relocation-isolation-audit', self.isolation)]
        self.result['tests'] = [{'name': name, 'status': 'not_run'} for name, _ in cases]
        self.save()
        for record, (name, function) in zip(self.result['tests'], cases):
            if time.monotonic() >= self.deadline:
                self.result['stop_reason'] = 'overall budget exhausted'
                break
            self.current = record
            self.case_dir = self.logs / name
            self.case_dir.mkdir()
            start = time.monotonic()
            self.case_deadline = min(start + CASE_SECONDS, self.deadline)
            record.update(status='running', commands=[], logs=str(self.case_dir))
            self.save()
            stop = False
            try:
                function()
                record['status'] = 'passed'
            except BaseException as exc:
                record['status'] = 'environment_denied' if isinstance(exc, EnvironmentDenied) else 'failed'
                record['error'] = str(exc) or type(exc).__name__
                (self.case_dir / 'failure.log').write_text(traceback.format_exc())
                if isinstance(exc, (Unsafe, OverallTimeout, KeyboardInterrupt, SystemExit)):
                    self.result['stop_reason'] = record['error']
                    stop = True
            record['seconds'] = round(time.monotonic() - start, 3)
            self.save()
            print(record['status'].upper() + ': ' + name +
                  (': ' + record['error'] if 'error' in record else ''), flush=True)
            if stop:
                break
        self.result['complete'] = all(r['status'] not in ('not_run', 'running') for r in self.result['tests'])
        statuses = [r['status'] for r in self.result['tests']]
        self.result['status'] = ('failed' if 'failed' in statuses else
                                 'partial' if not self.result['complete'] or 'environment_denied' in statuses
                                 else 'passed')
        self.result['counts'] = {s: statuses.count(s) for s in sorted(set(statuses))}
        self.save()


def main():
    def interrupted(signum, frame):
        raise OverallTimeout('overall timeout/interruption: ' + signal.Signals(signum).name)
    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
    suite = None
    try:
        suite = Suite()
        print('RESULTS: ' + str(suite.root / 'results.json'), flush=True)
        suite.execute()
    except BaseException as exc:
        if suite is None:
            traceback.print_exc()
            return 1
        suite.result.update(status='failed', complete=False, stop_reason=str(exc))
        (suite.logs / 'harness-failure.log').write_text(traceback.format_exc())
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if suite is not None:
            cleanup_errors = []
            for child in suite.owned:
                try:
                    child.close()
                except BaseException as exc:
                    cleanup_errors.append(str(exc))
            if cleanup_errors:
                suite.result.update(status='failed', cleanup_errors=cleanup_errors)
            suite.result['owned_children_reaped'] = all(c.p.returncode is not None for c in suite.owned)
            suite.save()
    print('SUMMARY: ' + json.dumps({'status': suite.result['status'],
          'complete': suite.result['complete'], 'counts': suite.result.get('counts'),
          'owned_children_reaped': suite.result['owned_children_reaped'],
          'results': str(suite.root / 'results.json')}), flush=True)
    return 0 if suite.result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
