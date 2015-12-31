package bismuth

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.org/x/crypto/ssh"
)

type Session interface {
	Close() error
	OnClose(onClose chan bool)
	SetCwd(cwd string)
	GetFullCmdShell() string
	SetCmdShell(cmd string)
	SetCmdArgs(args ...string)
	Start() (pid int, err error)
	Wait() (retCode int, err error)
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	SetStdin(reader io.Reader)
	SetStdout(writer io.Writer)
	SetStderr(writer io.Writer)
	Pid() int
}

var resultCodeEscapeBytes []byte = []byte{0x01, 0x7e, 0x12, 0x6b, 0x6a, 0x44, 0x7f, 0x21, 0x0b, 0x15, 0x1f, 0x4a, 0x0d, 0x67}
var resultCodeEscapeString string = fmt.Sprintf("%s", resultCodeEscapeBytes)

func getWrappedShellCommand(cmd string) string {
	return shellquote.Join("sh", "-c", "echo $$ >&2;"+cmd) + ";printf " + resultCodeEscapeString + "\"$?\\n\" >&2"
	// To run this yourself: log.Printf("%s\n", shellquote.Join("sh", "-c", s))
}

func getShellCommand(cwd string, execCmd string, includeExec bool) string {
	cmd := ""
	if cwd != "" {
		cmd += shellquote.Join("cd", cwd) + " && "
	}
	if includeExec {
		cmd += "exec "
	}
	return cmd + execCmd
}

const pidReceiveTimeout = 3 * time.Second

var timeoutError error = errors.New("timed out")

func receiveParseInt(strChan chan string) (int, error) {
	select {
	case str := <-strChan:
		val, err := strconv.ParseInt(str, 10, 32)
		if err != nil {
			return -1, err
		}
		return int(val), nil
	case <-time.After(pidReceiveTimeout):
		return -1, timeoutError
	}
}

type PseudoCloser struct {
	io.Writer
	onCloses []func()
}

func (p *PseudoCloser) Close() error {
	for _, onClose := range p.onCloses {
		onClose()
	}
	return nil
}
func (p *PseudoCloser) OnClose(cb func()) {
	p.onCloses = append(p.onCloses, cb)
}

func NewPseudoCloser(writer io.Writer) *PseudoCloser {
	return &PseudoCloser{writer, nil}
}

func callClosers(onCloses chan chan bool) {
	for {
		select {
		case onCloseChan := <-onCloses:
			onCloseChan <- true
		// OnClose and Close could be called concurrently; this is
		// an ugly hack to close that gap:
		case <-time.After(10 * time.Second):
			return
		}
	}
}

// Extend ssh.Session so that it implements the Session interface
type SshSession struct {
	*ssh.Session
	cwd         string
	shellCmd    string
	retCodeChan chan string
	pid         int
	onCloses    chan chan bool
}

func NewSshSession(_session *ssh.Session) *SshSession {
	s := &SshSession{}
	s.Session = _session
	s.onCloses = make(chan chan bool, 5)
	return s
}
func (s *SshSession) SetStdin(reader io.Reader)  { s.Stdin = reader }
func (s *SshSession) SetStdout(writer io.Writer) { s.Stdout = writer }
func (s *SshSession) SetStderr(writer io.Writer) { s.Stderr = writer }
func (s *SshSession) SetCwd(cwd string)          { s.cwd = cwd }
func (s *SshSession) getFullCmdShell() string    { return getShellCommand(s.cwd, s.shellCmd, true) }
func (s *SshSession) GetFullCmdShell() string    { return getShellCommand(s.cwd, s.shellCmd, false) }
func (s *SshSession) SetCmdShell(cmd string)     { s.shellCmd = cmd }
func (s *SshSession) SetCmdArgs(args ...string)  { s.SetCmdShell(shellquote.Join(args...)) }
func (s *SshSession) Start() (pid int, err error) {
	pidChan := make(chan string, 1)
	s.retCodeChan = make(chan string, 1)
	s.Stderr = NewFilteredWriter(s.Stderr, pidChan, s.retCodeChan)
	err = s.Session.Start(getWrappedShellCommand(s.getFullCmdShell()))
	if err != nil {
		return -1, err
	}
	s.pid, err = receiveParseInt(pidChan)
	if err == timeoutError {
		return -1, errors.New("Timed out waiting for PID")
	}
	return s.pid, err
}
func (s *SshSession) Wait() (retCode int, err error) {
	err = s.Session.Wait()
	if err != nil {
		return -1, err
	}
	retCode, err = receiveParseInt(s.retCodeChan)
	if err == timeoutError {
		return -1, errors.New("Timed out waiting for retCode")
	}
	return retCode, err
}
func (s *SshSession) Pid() (pid int) { return s.pid }
func (s *SshSession) Close() error {
	go callClosers(s.onCloses)
	return s.Session.Close()
}
func (s *SshSession) OnClose(onClose chan bool) {
	s.onCloses <- onClose
}

type LocalSession struct {
	*exec.Cmd
	pid      int
	onCloses chan chan bool
}

func NewLocalSession() *LocalSession {
	s := &LocalSession{}
	s.Cmd = &exec.Cmd{}
	s.Stdin = nil
	s.onCloses = make(chan chan bool, 5)
	s.Env = os.Environ() // Prevent side-effects/changes to Environ?
	return s
}
func (s *LocalSession) SetStdin(reader io.Reader)  { s.Stdin = reader }
func (s *LocalSession) SetStdout(writer io.Writer) { s.Stdout = writer }
func (s *LocalSession) SetStderr(writer io.Writer) { s.Stderr = writer }
func (s *LocalSession) SetCwd(cwd string)          { s.Dir = cwd }
func (s *LocalSession) GetFullCmdShell() string {
	return getShellCommand(s.Dir, shellquote.Join(s.Args...), false)
}
func (s *LocalSession) SetCmdShell(cmd string)    { s.Args = []string{"sh", "-c", cmd} }
func (s *LocalSession) SetCmdArgs(args ...string) { s.Args = args }
func (s *LocalSession) Start() (pid int, err error) {
	s.Path, err = exec.LookPath(s.Args[0])
	if err != nil {
		return -1, err
	}
	err = s.Cmd.Start()
	if err != nil {
		return -1, err
	}
	return s.Cmd.Process.Pid, err
}
func (s *LocalSession) Wait() (retCode int, err error) {
	err = s.Cmd.Wait()
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			return -1, err
		}
		waitStatus, ok := exitError.Sys().(syscall.WaitStatus)
		if ok {
			retCode = waitStatus.ExitStatus()
		} else {
			// Not really true. But it wasn't 0. TODO: Make this work in Windows
			retCode = -1
		}
	} else {
		retCode = 0
	}
	return retCode, err
}
func (s *LocalSession) Pid() (pid int) {
	if s.Cmd.Process != nil {
		return s.Cmd.Process.Pid
	} else {
		return -1
	}
}
func (s *LocalSession) Close() error {
	go callClosers(s.onCloses)
	return nil
}
func (s *LocalSession) OnClose(onClose chan bool) {
	s.onCloses <- onClose
}
func (s *LocalSession) StdoutPipe() (io.Reader, error) {
	readCloser, err := s.Cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	reader := readCloser.(io.Reader)
	return reader, nil
}
