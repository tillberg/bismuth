package bismuth

import (
    "fmt"
    "net"
    "os"
    "sync"
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/agent"
    "github.com/tillberg/ansi-log"
)

const maxSessions = 5

type ExecContext struct {
    mutex      sync.Mutex
    username   string
    hostname   string
    port       int
    client     *ssh.Client

    numRunning int
    numWaiting int
    poolDone   chan bool
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
    if ctx.client != nil {
        ctx.client.Close()
        ctx.client = nil
    }
}
func (ctx *ExecContext) getClient() (*ssh.Client, error) {
    if ctx.client == nil {
        agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
        if err != nil { return nil, err }
        defer agentConn.Close()
        ag := agent.NewClient(agentConn)
        auths := []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}
        config := &ssh.ClientConfig{
            User: ctx.username,
            Auth: auths,
        }
        client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ctx.hostname, ctx.port), config)
        if err != nil { return nil, err }
        ctx.client = client
    }
    return ctx.client, nil
}

func (ctx *ExecContext) makeSession() (*ssh.Session, error) {
    ctx.lock()
    if ctx.numRunning < maxSessions {
        ctx.numRunning++
    } else {
        ctx.numWaiting++
        ctx.unlock()
        <-ctx.poolDone
        ctx.lock()
    }
    client, err := ctx.getClient()
    if err != nil { return nil, err }
    session, err := client.NewSession()
    if err != nil { return nil, err }
    ctx.unlock()
    return session, nil
}

func (ctx *ExecContext) closeSession(session *ssh.Session) {
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
    session.Stdout = stdout
    session.Stderr = stderr
    err = session.Run(s)
    ctx.closeSession(session)
    return err
}

func (ctx *ExecContext) Close() {
    ctx.mutex.Lock()
    defer ctx.mutex.Unlock()
    ctx.close()
}
