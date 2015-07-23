package bismuth

import (
    "bufio"
    "bytes"
    "errors"
    "fmt"
    "io"
    "net"
    "os"
    "os/exec"
    "path"
    "strings"
    "sync"
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/agent"
    "github.com/kballard/go-shellquote"
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

    logger     *log.Logger
    nameAnsi   string

    uname      string
    env        map[string]string
}

var onceInit sync.Once

func (ctx *ExecContext) Init() {
    ctx.poolDone = make(chan bool)
    ctx.port = 22
    ctx.env = make(map[string]string)

    onceInit.Do(func () {
        log.AddAnsiColorCode("host", 33)
        log.AddAnsiColorCode("path", 36)
    })
    ctx.logger = ctx.newLogger("")
    ctx.updatedHostname()

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
        stdout, err := ctx.Output("uname")
        if err != nil {
            done<-err
        } else {
            ctx.uname = strings.TrimSpace(string(stdout))
            done<-nil
        }
    })
    doTask(func() {
        stdout, err := ctx.Output("env")
        if err != nil {
            done<-err
        } else {
            scanner := bufio.NewScanner(strings.NewReader(string(stdout)))
            for scanner.Scan() {
                line := scanner.Text()
                parts := strings.SplitN(line, "=", 2)
                if len(parts) < 2 {
                    done<-errors.New(fmt.Sprintf("Could not parse env line [%s]", line))
                    return
                }
                ctx.env[parts[0]] = parts[1]
            }
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
    ctx.updatedHostname()
}

func (ctx *ExecContext) updatedHostname() {
    hostname := ctx.hostname
    if hostname == "" { hostname = "localhost" }
    ctx.nameAnsi = ctx.logger.Colorify(fmt.Sprintf("@(host:%s)", hostname))
    ctx.logger.SetPrefix(fmt.Sprintf("@(dim)[%s] ", ctx.nameAnsi))
}

func (ctx *ExecContext) NameAnsi() string {
    ctx.lock()
    defer ctx.unlock()
    return ctx.nameAnsi
}

func (ctx *ExecContext) newLogger(suffix string) *log.Logger {
    logger := log.New(os.Stderr, "", 0)
    prefix := fmt.Sprintf("@(dim)[%s] ", ctx.nameAnsi)
    if len(suffix) > 0 {
        prefix = fmt.Sprintf("@(dim)[%s:%s] ", ctx.nameAnsi, suffix)
    }
    logger.EnableColorTemplate()
    logger.SetPrefix(prefix)
    return logger
}

func (ctx *ExecContext) NewLogger(suffix string) *log.Logger {
    ctx.lock()
    defer ctx.unlock()
    return ctx.newLogger(suffix)
}

func (ctx *ExecContext) Logger() *log.Logger {
    ctx.lock()
    defer ctx.unlock()
    return ctx.logger
}

func (ctx *ExecContext) startCmdAndWait(session Session, s string) (int, error) {
    err := session.Start(s)
    if err != nil { return -1, err }
    defer ctx.closeSession(session)
    err = session.Wait()
    if err != nil {
        if exitError, ok := err.(*ssh.ExitError); ok {
            retCode := exitError.ExitStatus()
            if retCode > 0 {
                return retCode, nil
            }
            return retCode, err
        }
        return -1, err
    }
    return 0, nil
}

func (ctx *ExecContext) QuoteShell(suffix string, s string) error {
    session, err := ctx.makeSession()
    if err != nil { return err }
    stdout := ctx.newLogger(suffix)
    defer stdout.Close()
    stderr := ctx.newLogger(fmt.Sprintf("%s/err", suffix))
    defer stderr.Close()
    session.SetStdout(stdout)
    session.SetStderr(stderr)
    _, err = ctx.startCmdAndWait(session, s)
    return err
}

func (ctx *ExecContext) Quote(suffix string, args ...string) error {
    return ctx.QuoteShell(suffix, shellquote.Join(args...))
}

func (ctx *ExecContext) RunShell(s string) (stdout []byte, stderr []byte, retCode int, err error) {
    session, err := ctx.makeSession()
    if err != nil { return nil, nil, -1, err }
    var bufOut bytes.Buffer
    var bufErr bytes.Buffer
    session.SetStdout(&bufOut)
    session.SetStderr(&bufErr)
    retCode, err = ctx.startCmdAndWait(session, s)
    return bufOut.Bytes(), bufErr.Bytes(), retCode, nil
}

func (ctx *ExecContext) Run(args ...string) (stdout []byte, stderr []byte, retCode int, err error) {
    return ctx.RunShell(shellquote.Join(args...))
}

func (ctx *ExecContext) OutputShell(s string) (stdout []byte, err error) {
    stdout, _, _, err = ctx.RunShell(s)
    return stdout, err
}

func (ctx *ExecContext) Output(args ...string) (stdout []byte, err error) {
    return ctx.OutputShell(shellquote.Join(args...))
}

func (ctx *ExecContext) AbsPath(p string) string {
    if p[:2] == "~/" {
        p = p[:2]
    }
    if !path.IsAbs(p) {
        p = path.Join([]string{ctx.env["HOME"], p}...)
    }
    return path.Clean(p)
}

func (ctx *ExecContext) Stat(p string) (os.FileInfo, error) {
    flagStr := "-c"
    formatStr := "%F,%f,%s,%Y"
    if ctx.IsDarwin() {
        flagStr = "-f"
        formatStr = "%HT,%Xp,%z,%m"
    }
    p = ctx.AbsPath(p)
    stdout, _, retcode, err := ctx.Run("stat", flagStr, formatStr, p)
    // log.Printf("stat %s -- %s\n", p, strings.TrimSpace(string(stdout)))
    if err != nil { return nil, err }
    if retcode != 0 { return nil, nil }
    fileInfo, err := NewFileInfoIsh(p, string(stdout))
    if err != nil { return nil, err }
    return fileInfo, nil
}

func (ctx *ExecContext) PathExists(path string) (bool, error) {
    stat, err := ctx.Stat(path)
    if err != nil { return false, err }
    return stat != nil, nil
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
