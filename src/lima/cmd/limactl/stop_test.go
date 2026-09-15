package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	hostagentevents "github.com/lima-vm/lima/pkg/hostagent/events"
	"github.com/lima-vm/lima/pkg/osutil"
	"github.com/lima-vm/lima/pkg/store"
	"github.com/lima-vm/lima/pkg/store/filenames"
)

const stopTestTimeout = 5 * time.Second

type stopTestProcess struct {
	pid   int
	input io.WriteCloser
	done  chan struct{}
	err   error
}

func startStopTestProcess(t *testing.T) *stopTestProcess {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("process termination tests require a POSIX shell and kill(pid, 0)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// Shell builtins keep the captured PID alive without spawning descendants.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf ready; IFS= read -r release")
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = input.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = input.Close()
		_ = output.Close()
		t.Fatal(err)
	}
	process := &stopTestProcess{pid: cmd.Process.Pid, input: input, done: make(chan struct{})}
	go func() {
		process.err = cmd.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = input.Close()
		select {
		case <-process.done:
		case <-time.After(stopTestTimeout):
			t.Errorf("child process %d was not reaped during cleanup", process.pid)
		}
	})
	defer output.Close()
	ready := make([]byte, len("ready"))
	if _, err := io.ReadFull(output, ready); err != nil {
		t.Fatalf("child process readiness: %v", err)
	}
	if string(ready) != "ready" {
		t.Fatalf("child process readiness = %q", ready)
	}
	process.assertAlive(t)
	return process
}

func (p *stopTestProcess) assertAlive(t *testing.T) {
	t.Helper()
	if err := osutil.SysKill(p.pid, 0); err != nil {
		t.Fatalf("child process %d should still be alive: %v", p.pid, err)
	}
}

func (p *stopTestProcess) release(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(p.input, "release\n"); err != nil {
		t.Fatalf("releasing child process %d: %v", p.pid, err)
	}
	if err := p.input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("child process %d exited unsuccessfully: %v", p.pid, p.err)
		}
	case <-time.After(stopTestTimeout):
		t.Fatalf("child process %d did not exit after release", p.pid)
	}
	// Reap before probing: a zombie can still answer kill(pid, 0).
	if err := osutil.SysKill(p.pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("reaped child process %d: kill(pid, 0) = %v, want ESRCH", p.pid, err)
	}
}

func startStopTestCall(t *testing.T, cancel context.CancelFunc, call func() error) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		result <- call()
		close(result)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-result:
		case <-time.After(stopTestTimeout):
			t.Error("shutdown wait did not return after cleanup cancellation")
		}
	})
	return result
}

func stopTestResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(stopTestTimeout):
		t.Fatal("shutdown wait did not return within the test timeout")
		return nil
	}
}

type stopTestPollContext struct {
	context.Context
	polls chan struct{}
}

func (c *stopTestPollContext) Done() <-chan struct{} {
	// The helper evaluates Done after probing its captured PIDs. Observe that
	// point without delaying it or substituting the process-liveness checks.
	select {
	case c.polls <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

func stopTestPoll(t *testing.T, polls <-chan struct{}, result <-chan error) {
	t.Helper()
	select {
	case <-polls:
	case err := <-result:
		t.Fatalf("shutdown wait returned while a captured process was alive: %v", err)
	case <-time.After(stopTestTimeout):
		t.Fatal("shutdown wait did not reach a process polling interval")
	}
	select {
	case err := <-result:
		t.Fatalf("shutdown wait returned while a captured process was alive: %v", err)
	default:
	}
}

func TestWaitForHostAgentTerminationExitingEventWaitsForProcesses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hostAgent bool
		qemu      bool
	}{
		{name: "host_agent_alive_without_pidfiles", hostAgent: true},
		{name: "qemu_alive_without_pidfiles", qemu: true},
		{name: "both_alive_without_pidfiles", hostAgent: true, qemu: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := &store.Instance{Dir: t.TempDir()}
			var processes []*stopTestProcess
			if tc.hostAgent {
				process := startStopTestProcess(t)
				inst.HostAgentPID = process.pid
				processes = append(processes, process)
			}
			if tc.qemu {
				process := startStopTestProcess(t)
				inst.QemuPID = process.pid
				processes = append(processes, process)
			}
			begin := time.Now()
			data, err := json.Marshal(hostagentevents.Event{
				Time: begin, Status: hostagentevents.Status{Exiting: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(inst.Dir, filenames.HostAgentStdoutLog), append(data, byte(10)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(inst.Dir, filenames.HostAgentStderrLog), nil, 0600); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{filenames.HostAgentPID, filenames.QemuPID} {
				if _, err := os.Stat(filepath.Join(inst.Dir, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("PID file %s must be absent: %v", name, err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			result := startStopTestCall(t, cancel, func() error {
				return waitForHostAgentTermination(ctx, inst, begin)
			})
			if err := stopTestResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("exiting event with live processes: got %v, want wrapped DeadlineExceeded", err)
			}
			for _, process := range processes {
				process.assertAlive(t)
				process.release(t)
			}

			finishedCtx, finishedCancel := context.WithTimeout(context.Background(), stopTestTimeout)
			finished := startStopTestCall(t, finishedCancel, func() error {
				return waitForHostAgentTermination(finishedCtx, inst, begin)
			})
			if err := stopTestResult(t, finished); err != nil {
				t.Fatalf("exiting event after both captured processes exited: %v", err)
			}
		})
	}
}

func TestWaitForInstanceProcessesWaitsForBothOriginalPIDs(t *testing.T) {
	for _, first := range []string{"host_agent", "qemu"} {
		t.Run(first+"_exits_first", func(t *testing.T) {
			hostAgent := startStopTestProcess(t)
			qemu := startStopTestProcess(t)
			inst := &store.Instance{Dir: t.TempDir(), HostAgentPID: hostAgent.pid, QemuPID: qemu.pid}
			ctx, cancel := context.WithTimeout(context.Background(), stopTestTimeout)
			observed := &stopTestPollContext{Context: ctx, polls: make(chan struct{}, 1)}
			result := startStopTestCall(t, cancel, func() error {
				return waitForInstanceProcesses(observed, inst)
			})
			stopTestPoll(t, observed.polls, result)
			firstProcess, lastProcess := hostAgent, qemu
			if first == "qemu" {
				firstProcess, lastProcess = qemu, hostAgent
			}
			firstProcess.release(t)
			// Discard a pending notification, then observe two more intervals so
			// even a probe in flight at release cannot satisfy the assertion.
			select {
			case <-observed.polls:
			default:
			}
			stopTestPoll(t, observed.polls, result)
			stopTestPoll(t, observed.polls, result)
			lastProcess.assertAlive(t)
			lastProcess.release(t)
			if err := stopTestResult(t, result); err != nil {
				t.Fatalf("both captured processes exited: %v", err)
			}
			if inst.HostAgentPID != hostAgent.pid || inst.QemuPID != qemu.pid {
				t.Fatalf("wait changed the original instance PIDs: host agent %d, QEMU %d", inst.HostAgentPID, inst.QemuPID)
			}
		})
	}
}

func TestWaitForInstanceProcessesHonorsDeadline(t *testing.T) {
	process := startStopTestProcess(t)
	inst := &store.Instance{HostAgentPID: process.pid}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	result := startStopTestCall(t, cancel, func() error {
		return waitForInstanceProcesses(ctx, inst)
	})
	if err := stopTestResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("live process at deadline: got %v, want wrapped DeadlineExceeded", err)
	}
	process.assertAlive(t)
	process.release(t)
}

func TestWaitForInstanceProcessesHonorsCancellation(t *testing.T) {
	process := startStopTestProcess(t)
	inst := &store.Instance{QemuPID: process.pid}
	ctx, cancel := context.WithTimeout(context.Background(), stopTestTimeout)
	observed := &stopTestPollContext{Context: ctx, polls: make(chan struct{}, 1)}
	result := startStopTestCall(t, cancel, func() error {
		return waitForInstanceProcesses(observed, inst)
	})
	stopTestPoll(t, observed.polls, result)
	cancel()
	if err := stopTestResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait for live process: got %v, want wrapped Canceled", err)
	}
	process.assertAlive(t)
	process.release(t)
}

func TestWaitForInstanceProcessesEmptyOrDeadPIDs(t *testing.T) {
	hostAgent := startStopTestProcess(t)
	qemu := startStopTestProcess(t)
	hostAgent.release(t)
	qemu.release(t)
	for _, tc := range []struct {
		name         string
		hostAgentPID int
		qemuPID      int
	}{
		{name: "zero"},
		{name: "negative", hostAgentPID: -1, qemuPID: -1},
		{name: "dead_host_agent", hostAgentPID: hostAgent.pid},
		{name: "dead_qemu", qemuPID: qemu.pid},
		{name: "both_dead", hostAgentPID: hostAgent.pid, qemuPID: qemu.pid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := &store.Instance{HostAgentPID: tc.hostAgentPID, QemuPID: tc.qemuPID}
			ctx, cancel := context.WithTimeout(context.Background(), stopTestTimeout)
			result := startStopTestCall(t, cancel, func() error {
				return waitForInstanceProcesses(ctx, inst)
			})
			if err := stopTestResult(t, result); err != nil {
				t.Fatalf("empty/dead PIDs: %v", err)
			}
		})
	}
}
