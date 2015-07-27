package bismuth

import (
    "errors"
    "fmt"
    "io"
    "os/exec"
    "strconv"
    "time"
    "golang.org/x/crypto/ssh"
    "github.com/kballard/go-shellquote"
)

type Session interface {
    Close() error
    SetCwd(cwd string)
    GetFullCmdShell() string
    SetCmdShell(cmd string)
    SetCmdArgs(args ...string)
    Start() (pid int, err error)
    Wait() (retCode int, err error)
    StdinPipe() (io.WriteCloser, error)
    StdoutPipe() (io.Reader, error)
    SetStdout(writer io.WriteCloser)
    SetStderr(writer io.WriteCloser)
    Pid() int
}

var resultCodeEscapeBytes []byte = []byte{0x01, 0x7e, 0x12, 0x6b, 0x6a, 0x44, 0x7f, 0x21, 0x0b, 0x15, 0x1f, 0x4a, 0x0d, 0x67 }
var resultCodeEscapeString string = fmt.Sprintf("%s", resultCodeEscapeBytes)
func getWrappedShellCommand(cmd string) string {
    return shellquote.Join("sh", "-c", "echo $$ >&2;" + cmd) + ";printf " + resultCodeEscapeString + "\"$?\\n\" >&2"
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
        if err != nil { return -1, err }
        return int(val), nil
    case <-time.After(pidReceiveTimeout):
        return -1, timeoutError
    }
}

type PseudoCloser struct {
    io.Writer
    onClose func()
}
func (p *PseudoCloser) Close() error {
    if p.onClose != nil { p.onClose() }
    return nil
}
func (p *PseudoCloser) OnClose(cb func()) {
    p.onClose = cb
}

func NewPseudoCloser(writer io.Writer) *PseudoCloser {
    return &PseudoCloser{writer, nil}
}

// Extend ssh.Session so that it implements the Session interface
type SshSession struct {
    *ssh.Session
    cwd         string
    shellCmd    string
    retCodeChan chan string
    pid         int
}
func NewSshSession(_session *ssh.Session) *SshSession {
    s := &SshSession{}
    s.Session = _session
    return s
}
func (s *SshSession) SetStdout(writer io.WriteCloser) { s.Stdout = writer }
func (s *SshSession) SetStderr(writer io.WriteCloser) { s.Stderr = writer }
func (s *SshSession) SetCwd(cwd string) { s.cwd = cwd }
func (s *SshSession) getFullCmdShell() string { return getShellCommand(s.cwd, s.shellCmd, true) }
func (s *SshSession) GetFullCmdShell() string { return getShellCommand(s.cwd, s.shellCmd, false) }
func (s *SshSession) SetCmdShell(cmd string) { s.shellCmd = cmd }
func (s *SshSession) SetCmdArgs(args ...string) { s.SetCmdShell(shellquote.Join(args...)) }
func (s *SshSession) Start() (pid int, err error) {
    pidChan := make(chan string, 1)
    s.retCodeChan = make(chan string, 1)
    var tmp io.WriteCloser
    if s.Stderr != nil {
        tmp = NewPseudoCloser(s.Stderr)
    }
    s.Stderr = NewFilteredWriter(tmp, pidChan, s.retCodeChan)
    err = s.Session.Start(getWrappedShellCommand(s.getFullCmdShell()))
    if err != nil { return -1, err }
    s.pid, err = receiveParseInt(pidChan)
    if err == timeoutError { return -1, errors.New("Timed out waiting for PID") }
    return s.pid, err
}
func (s *SshSession) Wait() (retCode int, err error) {
    err = s.Session.Wait()
    if err != nil { return -1, err }
    retCode, err = receiveParseInt(s.retCodeChan)
    if err == timeoutError { return -1, errors.New("Timed out waiting for retCode") }
    return retCode, err
}
func (s *SshSession) Pid() (pid int) { return s.pid }

type LocalSession struct {
    *exec.Cmd
    cwd         string
    shellCmd    string
    retCodeChan chan string
    pid         int
}
func NewLocalSession() *LocalSession {
    s := &LocalSession{}
    s.Cmd = exec.Command("sh", "tbd")
    s.Cmd.Stdin = nil
    return s
}
func (s *LocalSession) SetStdout(writer io.WriteCloser) { s.Stdout = writer }
func (s *LocalSession) SetStderr(writer io.WriteCloser) { s.Stderr = writer }
func (s *LocalSession) SetCwd(cwd string) { s.cwd = cwd }
func (s *LocalSession) getFullCmdShell() string { return getShellCommand(s.cwd, s.shellCmd, true) }
func (s *LocalSession) GetFullCmdShell() string { return getShellCommand(s.cwd, s.shellCmd, false) }
func (s *LocalSession) SetCmdShell(cmd string) { s.shellCmd = cmd }
func (s *LocalSession) SetCmdArgs(args ...string) { s.SetCmdShell(shellquote.Join(args...)) }
func (s *LocalSession) Start() (pid int, err error) {
    pidChan := make(chan string, 1)
    s.retCodeChan = make(chan string, 1)
    var tmp io.WriteCloser
    if s.Stderr != nil {
        tmp = NewPseudoCloser(s.Stderr)
    }
    s.Stderr = NewFilteredWriter(tmp, pidChan, s.retCodeChan)
    s.Args = []string{"sh", "-c", getWrappedShellCommand(s.getFullCmdShell())}
    err = s.Cmd.Start()
    if err != nil { return -1, err }
    s.pid, err = receiveParseInt(pidChan)
    if err == timeoutError { return -1, errors.New("Timed out waiting for PID") }
    return s.pid, err
}
func (s *LocalSession) Wait() (retCode int, err error) {
    err = s.Cmd.Wait()
    if err != nil { return -1, err }
    retCode, err = receiveParseInt(s.retCodeChan)
    if err == timeoutError { return -1, errors.New("Timed out waiting for retCode") }
    return retCode, err
}
func (s *LocalSession) Pid() (pid int) { return s.pid }
func (s *LocalSession) Close() error { return nil }
func (s *LocalSession) StdoutPipe() (io.Reader, error) {
    readCloser, err := s.Cmd.StdoutPipe()
    if err != nil { return nil, err }
    reader := readCloser.(io.Reader)
    return reader, nil
}

