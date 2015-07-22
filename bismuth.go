package bismuth

import (
    "bytes"
    "errors"
    "fmt"
    "io"
    "net"
    "os"
    "os/exec"
    "strings"
    "sync"
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/agent"
    "github.com/tillberg/ansi-log"
)

type Session interface {
    Close() error
    Start(cmd string) error
    Wait() error
    SetStdout(writer io.Writer)
    SetStderr(writer io.Writer)
}

// Extend ssh.Session so that it implements the Session interface
type SshSession struct {
    *ssh.Session
}
func (s *SshSession) SetStdout(writer io.Writer) { s.Stdout = writer }
func (s *SshSession) SetStderr(writer io.Writer) { s.Stderr = writer }

type LocalSession struct {
    cmd *exec.Cmd
    Stdout io.Writer
    Stderr io.Writer
}

func (s *LocalSession) Start(cmd string) error {
    bin, err := exec.LookPath("sh")
    if err != nil { return err }
    s.cmd = exec.Command(bin, "-c", cmd)
    s.cmd.Stdout = s.Stdout
    s.cmd.Stderr = s.Stderr
    return s.cmd.Start()
}

func (s *LocalSession) Wait() error {
    return s.cmd.Wait()
}

func (s *LocalSession) Close() error {
    return nil
}

func (s *LocalSession) SetStdout(writer io.Writer) { s.Stdout = writer }
func (s *LocalSession) SetStderr(writer io.Writer) { s.Stderr = writer }

const maxSessions = 5

type ExecContext struct {
    mutex      sync.Mutex
    username   string
    hostname   string
    port       int

    sshClient  *ssh.Client
    connected  bool

    numRunning int
    numWaiting int
    poolDone   chan bool

    uname      string
    home       string
}

func (ctx *ExecContext) Init() {
    ctx.poolDone = make(chan bool)
    ctx.port = 22
}
func NewExecContext() *ExecContext {
    ctx := &ExecContext{}
    ctx.Init()
    return ctx
}

func (ctx *ExecContext) lock() { ctx.mutex.Lock() }
func (ctx *ExecContext) unlock() { ctx.mutex.Unlock() }

func (ctx *ExecContext) close() {
    if ctx.sshClient != nil {
        ctx.sshClient.Close()
        ctx.sshClient = nil
    }
}

func (ctx *ExecContext) connect() error {
    ctx.lock()
    defer ctx.unlock()
    if ctx.connected {
        return errors.New("Already connected")
    }
    if ctx.hostname != "" {
        agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
        if err != nil { return err }
        defer agentConn.Close()
        ag := agent.NewClient(agentConn)
        auths := []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}
        config := &ssh.ClientConfig{
            User: ctx.username,
            Auth: auths,
        }
        ctx.sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", ctx.hostname, ctx.port), config)
        if err != nil { return err }
    }
    ctx.connected = true
    return nil
}

func (ctx *ExecContext) Connect() error {
    err := ctx.connect()
    if err != nil { return err }

    done := make(chan error)
    numTasks := 0
    doTask := func(fn func()) {
        numTasks++
        go fn()
    }
    doTask(func() {
        stdout, _, err := ctx.Run("uname")
        if err != nil {
            done<-err
        } else {
            ctx.uname = strings.TrimSpace(string(stdout))
            done<-nil
        }
    })
    doTask(func() {
        stdout, _, err := ctx.Run("echo $HOME")
        if err != nil {
            done<-err
        } else {
            ctx.home = strings.TrimSpace(string(stdout))
            done<-nil
        }
    })
    for i := 0; i < numTasks; i++ {
        err := <-done
        if err != nil {
            return err
        }
    }
    return nil
}

func (ctx *ExecContext) assertConnected() error {
    if !ctx.connected {
        return errors.New("Not connected. Call Connect first.")
    }
    return nil
}

func (ctx *ExecContext) _makeSession() (Session, error) {
    var session Session
    if ctx.hostname != "" {
        sshSession, err := ctx.sshClient.NewSession()
        if err != nil { return nil, err }
        session = &SshSession{sshSession}
    } else {
        session = &LocalSession{}
    }
    return session, nil
}

func (ctx *ExecContext) makeSession() (Session, error) {
    ctx.lock()
    defer ctx.unlock()
    err := ctx.assertConnected()
    if err != nil {
        return nil, err
    }
    if ctx.numRunning < maxSessions {
        ctx.numRunning++
    } else {
        ctx.numWaiting++
        ctx.unlock()
        <-ctx.poolDone
        ctx.lock()
    }
    return ctx._makeSession()
}

func (ctx *ExecContext) closeSession(session Session) {
    session.Close()
    ctx.lock()
    ctx.numRunning--
    if (ctx.numWaiting > 0) {
        ctx.poolDone<-true
        ctx.numWaiting--
    }
    ctx.unlock()
}

func (ctx *ExecContext) Username() string {
    ctx.lock()
    defer ctx.unlock()
    return ctx.username
}

func (ctx *ExecContext) Hostname() string {
    ctx.lock()
    defer ctx.unlock()
    return ctx.hostname
}

func (ctx *ExecContext) SetUsername(s string) {
    ctx.lock()
    defer ctx.unlock()
    ctx.close()
    ctx.username = s
}

func (ctx *ExecContext) SetHostname(s string) {
    ctx.lock()
    defer ctx.unlock()
    ctx.close()
    ctx.hostname = s
}

func (ctx *ExecContext) RunShell(s string) error {
    session, err := ctx.makeSession()
    if err != nil { return err }
    stdout := log.New(os.Stderr, "[out] ", 0)
    defer stdout.Close()
    stderr := log.New(os.Stderr, "[err] ", 0)
    defer stderr.Close()
    session.SetStdout(stdout)
    session.SetStderr(stderr)
    err = session.Start(s)
    if err != nil { return err }
    err = session.Wait()
    if err != nil { return err }
    ctx.closeSession(session)
    return err
}

func (ctx *ExecContext) Run(s string) (stdout []byte, stderr []byte, err error) {
    session, err := ctx.makeSession()
    if err != nil { return nil, nil, err }
    var bufOut bytes.Buffer
    var bufErr bytes.Buffer
    session.SetStdout(&bufOut)
    session.SetStderr(&bufErr)
    err = session.Start(s)
    if err != nil { return nil, nil, err }
    err = session.Wait()
    if err != nil { return nil, nil, err }
    ctx.closeSession(session)
    return bufOut.Bytes(), bufErr.Bytes(), nil
}

func (ctx *ExecContext) Close() {
    ctx.mutex.Lock()
    defer ctx.mutex.Unlock()
    ctx.close()
}

func (ctx *ExecContext) Uname() string {
    ctx.mutex.Lock()
    defer ctx.mutex.Unlock()
    err := ctx.assertConnected()
    if err != nil {
        panic(err)
    }
    return ctx.uname
}

func (ctx *ExecContext) IsWindows() bool {
    return ctx.Uname() == "Windows" // XXX this won't actually work
}

func (ctx *ExecContext) IsDarwin() bool {
    return ctx.Uname() == "Darwin"
}

func (ctx *ExecContext) IsLinux() bool {
    return ctx.Uname() == "Linux"
}
