from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--uefi", action="store_true", help="boot using embedded UEFI instead of legacy BIOS")
ARGS = parser.parse_args()
TEST = Path(tempfile.mkdtemp(prefix="b-", dir=ROOT/"tests"))
HOME, STATE, TMP, SHARE = [TEST/n for n in ["home", "state", "tmp", "share"]]
for p in [HOME, STATE, TMP, SHARE]: p.mkdir()
EXE = TEST / "limactl"
shutil.copy2(ROOT/"output/limactl", EXE)
ENV = os.environ.copy()
ENV.update(HOME=str(HOME), LIMA_HOME=str(STATE), TMPDIR=str(TMP), PATH="/usr/bin:/bin:/usr/sbin:/sbin")
for key in ["QEMU_SYSTEM_X86_64", "QEMU_IMG", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "SSH_AUTH_SOCK"]: ENV.pop(key, None)
NAME = "alpine"
CONFIG = TEST / "alpine.yaml"
CONFIG.write_text("\n".join([
    "arch: x86_64", "cpus: 2", "memory: 768MiB", "disk: 2GiB", "images:",
    "- location: " + json.dumps(str(ROOT/"downloads/alpine-lima-std-3.16.0-x86_64.iso")),
    "  arch: x86_64",
    "  digest: sha512:2fe71bb7483cb9fa9a6f39b94d46818d27815dbd41bfa060df2846719e0bddf8d9073627a50ed773d7043c996b59182832cd8ce74404cdae09057a5a54b4f1ca",
    "firmware:", "  legacyBIOS: " + ("false" if ARGS.uefi else "true"), "mountType: 9p", "mounts:",
    "- location: " + json.dumps(str(SHARE)), "  mountPoint: /mnt/singlefile-test", "  writable: true",
    "ssh:", "  loadDotSSHPubKeys: false", "containerd:", "  system: false", "  user: false", ""]))
(SHARE/"from-host").write_text("single-file-host\n")
RESULT = {"status": "running", "firmware": "uefi" if ARGS.uefi else "bios", "test_root": str(TEST), "cases": []}
print("BOOT TEST:", TEST, flush=True)

def run(label, args, timeout=30, expected=0):
    log = TEST / (label+".log")
    print("RUN:", label, "LOG:", log, flush=True)
    with log.open("wb") as out:
        proc = subprocess.Popen([str(EXE)] + args, env=ENV, cwd=TEST, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
        started = time.monotonic()
        try:
            while True:
                try:
                    code = proc.wait(timeout=min(20, max(0.1, timeout-(time.monotonic()-started))))
                    break
                except subprocess.TimeoutExpired:
                    lines = log.read_text(errors="replace").splitlines()
                    print(label, str(int(time.monotonic()-started))+"s:", lines[-1][:300] if lines else "running", flush=True)
                    if time.monotonic()-started >= timeout: raise TimeoutError(label+" timed out")
        except BaseException:
            proc.kill(); proc.wait(); raise
    output = log.read_text(errors="replace")
    RESULT["cases"].append({"name": label, "args": args, "returncode": code, "log": str(log)})
    if expected is not None and code != expected:
        print("\n".join(output.splitlines()[-30:]), flush=True)
        raise RuntimeError(label+" exited "+str(code))
    print("PASS:" if code == 0 else "EXIT "+str(code)+":", label, flush=True)
    return output

try:
    run("validate", ["validate", str(CONFIG)])
    run("start", ["--debug", "start", "--tty=false", "--name="+NAME, str(CONFIG)], 180)
    output = run("guest-architecture", ["shell", "--workdir=/", NAME, "uname", "-m"])
    assert "x86_64" in output
    output = run("guest-agent", ["shell", "--workdir=/", NAME, "pgrep", "-f", "lima-guestagent"])
    assert any(l.strip().isdigit() for l in output.splitlines()), output
    output = run("mount-read", ["shell", "--workdir=/", NAME, "cat", "/mnt/singlefile-test/from-host"])
    assert "single-file-host" in output, output
    run("mount-write", ["shell", "--workdir=/", NAME, "cp", "/mnt/singlefile-test/from-host", "/mnt/singlefile-test/from-guest"])
    assert (SHARE/"from-guest").read_text() == "single-file-host\n"
    run("stop", ["stop", NAME], 45)
    run("restart", ["start", "--tty=false", NAME], 150)
    output = run("after-restart", ["shell", "--workdir=/", NAME, "cat", "/mnt/singlefile-test/from-guest"])
    assert "single-file-host" in output
    run("final-stop", ["stop", NAME], 45)
    RESULT["status"] = "passed"
except BaseException as e:
    RESULT["status"] = "failed"
    RESULT["error"] = str(e)
    print("FAIL:", str(e), flush=True)
    instance = STATE / NAME
    if instance.is_dir():
        print("INSTANCE FILES:", [p.name for p in instance.iterdir()], flush=True)
        for p in instance.glob("*.log"):
            print("--- "+p.name+" ---\n"+"\n".join(p.read_text(errors="replace").splitlines()[-20:]), flush=True)
finally:
    if (STATE/NAME).is_dir():
        try: run("cleanup", ["stop", "--force", NAME], 30, expected=None)
        except Exception as e: RESULT["cleanup_error"] = str(e)
    (TEST/"results.json").write_text(json.dumps(RESULT, indent=2)+"\n")
    print("RESULT:", RESULT["status"], TEST/"results.json", flush=True)
raise SystemExit(0 if RESULT["status"] == "passed" and "cleanup_error" not in RESULT else 1)
