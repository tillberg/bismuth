package bismuth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/tillberg/ansi-log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxSessionsPerContext = 5
const networkTimeout = 15 * time.Second

type ExecContext struct {
	mutex    sync.Mutex
	username string
	hostname string
	port     int

	sshClient      *ssh.Client
	hasConnected   bool
	isConnected    bool
	isReconnecting bool

	sessions   []Session
	numWaiting int
	poolDone   chan bool

	logger    *log.Logger
	nameAnsi  string
	logPrefix string

	uname string
	env   map[string]string
}

var onceInit sync.Once

var verbose = false

func SetVerbose(_verbose bool) {
	verbose = _verbose
}

var NotFoundError = errors.New("not found")
var NotConnectedError = errors.New("not connected")
var NotHasConnectedError = errors.New("never connected")

func (ctx *ExecContext) Init() {
	ctx.poolDone = make(chan bool)
	ctx.port = 22
	ctx.env = make(map[string]string)

	onceInit.Do(func() {
		log.AddAnsiColorCode("host", 33)
	})
	ctx.logger = ctx.newLogger("")
	ctx.updatedHostname()

}
func NewExecContext() *ExecContext {
	ctx := &ExecContext{}
	ctx.Init()
	return ctx
}

func (ctx *ExecContext) lock()   { ctx.mutex.Lock() }
func (ctx *ExecContext) unlock() { ctx.mutex.Unlock() }

// From http://stackoverflow.com/questions/31554196/ssh-connection-timeout

// Conn wraps a net.Conn, and sets a deadline for every read
// and write operation.
type Conn struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (c *Conn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (ctx *ExecContext) close() {
	if ctx.sshClient != nil {
		ctx.sshClient.Close()
		ctx.sshClient = nil
	}
	ctx.isConnected = false
}

func (ctx *ExecContext) reconnect() (err error) {
	if ctx.hostname != "" {
		ctx.isReconnecting = true
		username := ctx.username
		addr := fmt.Sprintf("%s:%d", ctx.hostname, ctx.port)
		ctx.unlock()
		agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			ctx.lock()
			ctx.isReconnecting = false
			return err
		}
		defer agentConn.Close()
		ag := agent.NewClient(agentConn)
		auths := []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}
		config := &ssh.ClientConfig{
			User: username,
			Auth: auths,
		}
		conn, err := net.DialTimeout("tcp", addr, networkTimeout)
		if err != nil {
			ctx.lock()
			ctx.isReconnecting = false
			return err
		}

		timeoutConn := &Conn{conn, networkTimeout, networkTimeout}
		c, chans, reqs, err := ssh.NewClientConn(timeoutConn, addr, config)
		if err != nil {
			ctx.lock()
			ctx.isReconnecting = false
			return err
		}
		client := ssh.NewClient(c, chans, reqs)

		// Send periodic keepalive messages
		go func() {
			t := time.NewTicker(networkTimeout / 2)
			defer t.Stop()
			for {
				<-t.C
				_, _, err := client.Conn.SendRequest("keepalive@golang.org", true, nil)
				if err != nil {
					ctx.lock()
					if ctx.sshClient == client {
						ctx.isConnected = false
					}
					ctx.unlock()
					return
				}
			}
		}()
		ctx.lock()
		ctx.isReconnecting = false
		ctx.sshClient = client
	}
	ctx.isConnected = true
	return nil
}

// Adapted from bufio.ScanLines, replacing \n with \000
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}
func scanNullLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\000'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, dropCR(data[0:i]), nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), dropCR(data), nil
	}
	// Request more data.
	return 0, nil, nil
}

func (ctx *ExecContext) Connect() (err error) {
	ctx.lock()
	if ctx.isReconnecting {
		ctx.unlock()
		return errors.New("Another Connect call is in progress")
	}
	ctx.close()
	err = ctx.reconnect()
	if err != nil {
		ctx.unlock()
		return err
	}

	if ctx.hasConnected {
		ctx.unlock()
		return nil
	}
	ctx.hasConnected = true
	ctx.unlock()

	done := make(chan error)
	numTasks := 0
	doTask := func(fn func()) {
		numTasks++
		go fn()
	}
	unameDone := make(chan bool)
	doTask(func() {
		stdout, err := ctx.Output("uname")
		if err != nil {
			done <- err
		} else {
			ctx.uname = strings.TrimSpace(string(stdout))
			done <- nil
		}
		unameDone <- true
	})
	doTask(func() {
		<-unameDone
		useNullTerminator := !ctx.IsDarwin()
		envArgs := []string{"env"}
		if useNullTerminator {
			envArgs = append(envArgs, "-0")
		}
		stdout, err := ctx.Output(envArgs...)
		if err != nil {
			done <- err
		} else {
			scanner := bufio.NewScanner(strings.NewReader(stdout))
			if useNullTerminator {
				scanner.Split(scanNullLines)
			}
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.SplitN(line, "=", 2)
				if len(parts) < 2 {
					// Don't bother warning about errors on Darwin, but this Scanner should be fixed for it. Somehow.
					if useNullTerminator {
						done <- errors.New(fmt.Sprintf("Could not parse environment line [%s]", line))
						return
					}
					continue
				}
				ctx.env[parts[0]] = parts[1]
			}
			done <- nil
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

func (ctx *ExecContext) IsConnected() bool {
	ctx.lock()
	defer ctx.unlock()
	return ctx.isConnected
}

func (ctx *ExecContext) assertConnected() error {
	if !ctx.isConnected {
		return NotConnectedError
	}
	return nil
}

func (ctx *ExecContext) assertHasConnected() error {
	if !ctx.hasConnected {
		return NotHasConnectedError
	}
	return nil
}

func (ctx *ExecContext) makeSession() (session Session, err error) {
	if ctx.hostname != "" {
		sshSession, err := ctx.sshClient.NewSession()
		if err != nil {
			return nil, err
		}
		session = NewSshSession(sshSession)
	} else {
		session = NewLocalSession()
	}
	return session, nil
}

func (ctx *ExecContext) MakeSession() (Session, error) {
	ctx.lock()
	defer ctx.unlock()
	err := ctx.assertConnected()
	if err != nil {
		return nil, err
	}
	if len(ctx.sessions) >= maxSessionsPerContext {
		ctx.numWaiting++
		ctx.unlock()
		<-ctx.poolDone
		ctx.lock()
	}
	session, err := ctx.makeSession()
	if err != nil {
		return nil, err
	}
	ctx.sessions = append(ctx.sessions, session)
	return session, nil
}

func (ctx *ExecContext) CloseSession(session Session) {
	session.Close()
	ctx.lock()
	removed := false
	for i, otherSession := range ctx.sessions {
		if otherSession == session {
			if i == len(ctx.sessions)-1 {
				ctx.sessions = ctx.sessions[:i]
			} else {
				ctx.sessions = append(ctx.sessions[:i], ctx.sessions[i+1:]...)
			}
			removed = true
			break
		}
	}
	if !removed {
		ctx.logger.Printf("@(error:Failed to remove my session)\n")
	}
	if ctx.numWaiting > 0 {
		ctx.poolDone <- true
		ctx.numWaiting--
	}
	ctx.unlock()
}

const killTimeout = 2 * time.Second

func (ctx *ExecContext) KillAllSessions() {
	status := ctx.Logger()
	ctx.lock()
	if !ctx.isConnected {
		// There's no sense in trying to kill sessions from a dead connection
		ctx.unlock()
		return
	}
	sessions := ctx.sessions
	ctx.unlock()
	sessionClosedChan := make(chan bool, len(sessions))
	for _, session := range sessions {
		session.OnClose(sessionClosedChan)
		pid := session.Pid()
		if pid > 0 {
			var err error
			if ctx.IsLocal() {
				err = syscall.Kill(pid, syscall.SIGTERM)
			} else {
				_, err = ctx.Quote("kill", "kill", "-SIGTERM", fmt.Sprintf("%d", pid))
			}
			if err != nil {
				status.Printf("Failed to kill process %d: %v\n", pid, err)
			}
		}
	}
	timeoutChan := time.After(killTimeout)
	for _, _ = range sessions {
		select {
		case <-sessionClosedChan:
			break
		case <-timeoutChan:
			status.Printf("@(error:Timed out in KillAllSessions while waiting for processes to exit.)\n")
			return
		}
	}
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
	if hostname == "" {
		hostname = "localhost"
	}
	ctx.nameAnsi = ctx.logger.Colorify(fmt.Sprintf("@(host:%s)", hostname))
	ctx.logger.SetPrefix(fmt.Sprintf("@(dim)[%s] ", ctx.nameAnsi))
}

func (ctx *ExecContext) SshAddress() string {
	return fmt.Sprintf("%s@%s", ctx.Username(), ctx.Hostname())
}

func (ctx *ExecContext) NameAnsi() string {
	ctx.lock()
	defer ctx.unlock()
	return ctx.nameAnsi
}

func (ctx *ExecContext) SetLogPrefix(prefix string) {
	ctx.lock()
	defer ctx.unlock()
	ctx.logPrefix = prefix
}

func (ctx *ExecContext) newLogger(suffix string) *log.Logger {
	logger := log.New(os.Stderr, "", 0)
	prefix := fmt.Sprintf("@(dim)[%s] ", ctx.nameAnsi)
	if len(suffix) > 0 {
		prefix = fmt.Sprintf("@(dim)[%s:%s] ", ctx.nameAnsi, suffix)
	}
	logger.EnableColorTemplate()
	logger.SetPrefix(ctx.logPrefix + prefix)
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

func (ctx ExecContext) ReverseTunnel(srcAddr string, destAddr string) (listener net.Listener, errChan chan error, err error) {
	ctx.lock()
	defer ctx.unlock()
	if ctx.hostname == "" {
		return nil, nil, errors.New("ReverseTunnel not supported for local ExecContext")
	}
	listener, err = ctx.sshClient.Listen("tcp", srcAddr)
	if err != nil {
		return nil, nil, err
	}
	errChan = make(chan error)
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				errChan <- err
				return
			}
			go func() {
				defer client.Close()
				// Establish connection with remote server
				remote, err := net.Dial("tcp", destAddr)
				if err != nil {
					ctx.Logger().Printf("@(error:Error on reverse-tunnel dial: %v)\n", err)
				}
				chDone := make(chan bool)
				// Start remote -> local data transfer
				go func() {
					_, err := io.Copy(client, remote)
					if err != nil {
						ctx.Logger().Printf("@(error:Error on reverse-tunnel client->remote copy: %v)\n", err)
					}
					chDone <- true
				}()
				// Start local -> remote data transfer
				go func() {
					_, err := io.Copy(remote, client)
					if err != nil {
						ctx.Logger().Printf("@(error:Error on reverse-tunnel remote->client copy: %v)\n", err)
					}
					chDone <- true
				}()
				<-chDone
				<-chDone
			}()
		}
	}()
	return listener, errChan, nil
}

func (ctx *ExecContext) StartCmd(session Session) (pid int, retCodeChan chan int, err error) {
	cmdLog := ctx.newLogger("")
	if verbose {
		cmdLog.Printf("@(dim:$) %s", session.GetFullCmdShell())
	}
	pid, err = session.Start()
	if verbose {
		cmdLog.Printf(" @(dim)(@(r)@(blue:%d)@(dim))@(r)", pid)
	}
	if err != nil {
		return -1, nil, err
	}
	retCodeChan = make(chan int, 1)
	go func() {
		defer cmdLog.Close()
		defer ctx.CloseSession(session)
		// XXX We need to finish reading from stdout/stderr before calling Wait:
		// http://stackoverflow.com/questions/20134095/why-do-i-get-bad-file-descriptor-in-this-go-program-using-stderr-and-ioutil-re
		retCode, err := session.Wait()
		if verbose {
			if err != nil {
				cmdLog.Printf(" @(red:%v)", err)
			} else {
				color := "green"
				if retCode != 0 {
					color = "red"
				}
				cmdLog.Printf(" @(dim:->) @("+color+":%d)\n", retCode)
			}
		}
		retCodeChan <- retCode
	}()
	return pid, retCodeChan, err
}

type SessionSetupFn func(session Session, ready chan error, done chan bool)

func (ctx *ExecContext) StartSession(setupFns ...SessionSetupFn) (pid int, retCodeChan chan int, err error) {
	session, err := ctx.MakeSession()
	if err != nil {
		return -1, nil, err
	}
	ready := make(chan error, len(setupFns))
	done := make(chan bool, len(setupFns))
	cleanup := func() {
		for _, _ = range setupFns {
			done <- true
		}
	}
	for _, setupFn := range setupFns {
		go setupFn(session, ready, done)
		err = <-ready
		if err != nil {
			cleanup()
			return -1, nil, err
		}
	}
	pid, retCodeChan2, err := ctx.StartCmd(session)
	retCodeChan = make(chan int, 1)
	go func() {
		retCode := <-retCodeChan2
		cleanup()
		retCodeChan <- retCode
	}()
	return pid, retCodeChan, err
}

func (ctx *ExecContext) ExecSession(setupFns ...SessionSetupFn) (retCode int, err error) {
	_, retCodeChan, err := ctx.StartSession(setupFns...)
	if err != nil {
		return -1, err
	}
	retCode = <-retCodeChan
	return retCode, err
}

func (ctx *ExecContext) SessionQuoteOut(suffix string) SessionSetupFn {
	fn := func(session Session, ready chan error, done chan bool) {
		logger := ctx.newLogger(suffix)
		defer logger.Close()
		session.SetStdout(logger)
		ready <- nil
		<-done
	}
	return fn
}

func (ctx *ExecContext) SessionQuoteErr(suffix string) SessionSetupFn {
	fn := func(session Session, ready chan error, done chan bool) {
		logger := ctx.newLogger(suffix)
		defer logger.Close()
		session.SetStderr(logger)
		ready <- nil
		<-done
	}
	return fn
}

func SessionShell(cmd string) SessionSetupFn {
	fn := func(session Session, ready chan error, done chan bool) {
		session.SetCmdShell(cmd)
		ready <- nil
		<-done
	}
	return fn
}

func SessionArgs(args ...string) SessionSetupFn {
	fn := func(session Session, ready chan error, done chan bool) {
		session.SetCmdArgs(args...)
		ready <- nil
		<-done
	}
	return fn
}

func SessionCwd(cwd string) SessionSetupFn {
	fn := func(session Session, ready chan error, done chan bool) {
		session.SetCwd(cwd)
		ready <- nil
		<-done
	}
	return fn
}

type BufferCloser struct {
	bytes.Buffer
}

func (b BufferCloser) Close() error { return nil }

func SessionBuffer() (SessionSetupFn, chan []byte) {
	bufChan := make(chan []byte, 2)
	fn := func(session Session, ready chan error, done chan bool) {
		var bufOut BufferCloser
		var bufErr BufferCloser
		session.SetStdout(&bufOut)
		session.SetStderr(&bufErr)
		ready <- nil
		<-done
		bufChan <- bufOut.Bytes()
		bufChan <- bufErr.Bytes()
	}
	return fn, bufChan
}

func SessionPipeStdout(chanStdout chan io.Reader) SessionSetupFn {
	return func(session Session, ready chan error, done chan bool) {
		stdout, err := session.StdoutPipe()
		if err != nil {
			ready <- err
			return
		}
		ready <- nil
		chanStdout <- stdout
		<-done
	}
}

func SessionPipeStdin(chanStdin chan io.WriteCloser) SessionSetupFn {
	return func(session Session, ready chan error, done chan bool) {
		stdin, err := session.StdinPipe()
		if err != nil {
			ready <- err
			return
		}
		ready <- nil
		chanStdin <- stdin
		<-done
	}
}

func SessionSetStdin(reader io.Reader) SessionSetupFn {
	return func(session Session, ready chan error, done chan bool) {
		session.SetStdin(reader)
		ready <- nil
		<-done
	}
}

func SessionInteractive() SessionSetupFn {
	return func(session Session, ready chan error, done chan bool) {
		session.SetStdin(os.Stdin)
		session.SetStdout(os.Stdout)
		session.SetStderr(os.Stderr)
		ready <- nil
		<-done
	}
}

func (ctx *ExecContext) QuoteCwdPipeOut(suffix string, cwd string, chanStdout chan io.Reader, args ...string) (retCode int, err error) {
	return ctx.ExecSession(ctx.SessionQuoteErr(suffix), SessionPipeStdout(chanStdout), SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...))
}

func (ctx *ExecContext) QuoteCwdPipeIn(suffix string, cwd string, chanStdin chan io.WriteCloser, args ...string) (retCode int, err error) {
	return ctx.ExecSession(ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix), SessionPipeStdin(chanStdin), SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...))
}

func (ctx *ExecContext) QuoteCwdPipeInOut(suffix string, cwd string, chanStdin chan io.WriteCloser, chanStdout chan io.Reader, args ...string) (retCode int, err error) {
	return ctx.ExecSession(ctx.SessionQuoteErr(suffix), SessionPipeStdin(chanStdin), SessionPipeStdout(chanStdout), SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...))
}

func (ctx *ExecContext) ShellInteractive(s string) (retCode int, err error) {
	return ctx.ExecSession(SessionShell(s), SessionInteractive())
}

func (ctx *ExecContext) QuoteShell(suffix string, s string) (retCode int, err error) {
	return ctx.ExecSession(SessionShell(s), ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix))
}

func (ctx *ExecContext) QuoteCwdBuf(suffix string, cwd string, args ...string) (stdout []byte, stderr []byte, retCode int, err error) {
	bufSetup, bufChan := SessionBuffer()
	retCode, err = ctx.ExecSession(SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...), bufSetup, ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix))
	stdout = <-bufChan
	stderr = <-bufChan
	return stdout, stderr, retCode, err
}

func (ctx *ExecContext) QuoteCwd(suffix string, cwd string, args ...string) (retCode int, err error) {
	return ctx.ExecSession(SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...), ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix))
}

func (ctx *ExecContext) QuoteDaemonCwdPipeOut(suffix string, cwd string, chanStdout chan io.Reader, args ...string) (pid int, retCodeChan chan int, err error) {
	return ctx.StartSession(SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...), ctx.SessionQuoteErr(suffix), SessionPipeStdout(chanStdout))
}

func (ctx *ExecContext) QuoteDaemonCwd(suffix string, cwd string, args ...string) (pid int, retCodeChan chan int, err error) {
	return ctx.StartSession(SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...), ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix))
}

func (ctx *ExecContext) Quote(suffix string, args ...string) (retCode int, err error) {
	retCode, err = ctx.ExecSession(SessionArgs(args...), ctx.SessionQuoteOut(suffix), ctx.SessionQuoteErr(suffix))
	return retCode, err
}

func (ctx *ExecContext) RunShell(s string) (stdout []byte, stderr []byte, retCode int, err error) {
	bufSetup, bufChan := SessionBuffer()
	retCode, err = ctx.ExecSession(bufSetup, SessionShell(s))
	if err != nil {
		return nil, nil, -1, err
	}
	stdout = <-bufChan
	stderr = <-bufChan
	return stdout, stderr, retCode, err
}

func (ctx *ExecContext) RunCwd(cwd string, args ...string) (stdout []byte, stderr []byte, retCode int, err error) {
	bufSetup, bufChan := SessionBuffer()
	retCode, err = ctx.ExecSession(bufSetup, SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...))
	if err != nil {
		return nil, nil, -1, err
	}
	stdout = <-bufChan
	stderr = <-bufChan
	return stdout, stderr, retCode, err
}

func (ctx *ExecContext) Run(args ...string) (stdout []byte, stderr []byte, retCode int, err error) {
	bufSetup, bufChan := SessionBuffer()
	retCode, err = ctx.ExecSession(bufSetup, SessionArgs(args...))
	if err != nil {
		return nil, nil, -1, err
	}
	stdout = <-bufChan
	stderr = <-bufChan
	return stdout, stderr, retCode, err
}

func (ctx *ExecContext) OutputShell(s string) (stdout string, err error) {
	bufSetup, bufChan := SessionBuffer()
	_, err = ctx.ExecSession(bufSetup, SessionShell(s))
	if err != nil {
		return "", err
	}
	stdout = strings.TrimSpace(string(<-bufChan))
	<-bufChan // ignore stderr
	return stdout, err
}

func (ctx *ExecContext) OutputCwd(cwd string, args ...string) (stdout string, err error) {
	bufSetup, bufChan := SessionBuffer()
	_, err = ctx.ExecSession(bufSetup, SessionCwd(ctx.AbsPath(cwd)), SessionArgs(args...))
	if err != nil {
		return "", err
	}
	stdout = strings.TrimSpace(string(<-bufChan))
	<-bufChan // ignore stderr
	return stdout, err
}

func (ctx *ExecContext) Output(args ...string) (stdout string, err error) {
	bufSetup, bufChan := SessionBuffer()
	_, err = ctx.ExecSession(bufSetup, SessionArgs(args...))
	if err != nil {
		return "", err
	}
	stdout = strings.TrimSpace(string(<-bufChan))
	<-bufChan // ignore stderr
	return stdout, err
}

type uploadTask struct {
	isDir bool
	p     string
}

func (ctx *ExecContext) UploadRecursiveExcludes(srcRootPath string, destContext *ExecContext, destRootPath string, excludes []string) error {
	srcRootPath = ctx.AbsPath(srcRootPath)
	destRootPath = destContext.AbsPath(destRootPath)
	return ctx.uploadRecursiveTar(srcRootPath, destContext, destRootPath, excludes)
}

func (ctx *ExecContext) uploadRecursiveTar(srcRootPath string, destContext *ExecContext, destRootPath string, excludes []string) (err error) {
	chanErr := make(chan error)
	stdinChan := make(chan io.WriteCloser)
	go func() {
		err = destContext.Mkdirp(destRootPath)
		if err != nil {
			chanErr <- err
			return
		}
		untarArgs := []string{"tar", "xzf", "-", "-m"}
		_, err := destContext.QuoteCwdPipeIn("untar", destRootPath, stdinChan, untarArgs...)
		chanErr <- err
	}()
	ctxStdin := <-stdinChan
	tarArgs := []string{"tar", "czf", "-"}
	for _, exclude := range excludes {
		tarArgs = append(tarArgs, "--exclude="+exclude)
	}
	tarArgs = append(tarArgs, "./")
	stdoutChan := make(chan io.Reader)
	copyChan := make(chan error)
	go func() {
		stdout := <-stdoutChan
		_, err := io.Copy(ctxStdin, stdout)
		copyChan <- err
	}()
	_, err = ctx.QuoteCwdPipeOut("tar", srcRootPath, stdoutChan, tarArgs...)
	if err != nil {
		return err
	}
	err = <-copyChan
	if err != nil {
		return err
	}
	ctxStdin.Close()
	err = <-chanErr
	if err != nil {
		return err
	}
	return nil
}

func (ctx *ExecContext) uploadRecursiveFallback(srcRootPath string, destContext *ExecContext, destRootPath string, excludes []string) error {
	status := ctx.NewLogger("")
	excludeMap := make(map[string]bool)
	for _, exclude := range excludes {
		excludeMap[exclude] = true
	}
	numUploaders := maxSessionsPerContext
	tasks := make(chan *uploadTask, maxSessionsPerContext)
	errors := make(chan error)
	for i := 0; i < numUploaders; i++ {
		go func() {
			for {
				task := <-tasks
				if task == nil {
					break
				}
				destPath := path.Join(destRootPath, task.p)
				if task.isDir {
					status.Printf("@(error:mkdir -p) %s\n", destPath)
					err := destContext.Mkdirp(destPath)
					if err != nil {
						errors <- err
						return
					}
				} else {
					srcPath := path.Join(srcRootPath, task.p)
					status.Printf("@(error:upload) %s -> %s\n", srcPath, destPath)
					contents, err := ctx.ReadFile(srcPath)
					if err != nil {
						errors <- err
						return
					}
					err = destContext.WriteFile(destPath, contents)
					if err != nil {
						errors <- err
						return
					}
				}
			}
			errors <- nil
		}()
	}
	var uploadDir func(string) error
	uploadDir = func(p string) (err error) {
		tasks <- &uploadTask{true, p}
		srcPath := path.Join(srcRootPath, p)
		filenames, err := ctx.ListDirectory(srcPath)
		if err != nil {
			return err
		}
		for _, filename := range filenames {
			_, excluded := excludeMap[filename]
			if excluded {
				continue
			}
			subPath := path.Join(p, filename)
			stat, err := ctx.Stat(path.Join(srcRootPath, subPath))
			if err == NotFoundError {
				status.Printf("@(error:Failed to stat) %s\n", subPath)
				continue
			}
			if err != nil {
				return err
			}
			if stat.IsDir() {
				err = uploadDir(subPath)
				if err != nil {
					return err
				}
			} else {
				tasks <- &uploadTask{false, subPath}
			}
		}
		return nil
	}
	go func() {
		rootStat, err := ctx.Stat(srcRootPath)
		if err != nil {
			errors <- err
			return
		}
		if rootStat.IsDir() {
			err = uploadDir(".")
			if err != nil {
				errors <- err
				return
			}
		} else {
			tasks <- &uploadTask{false, "."}
		}
		for i := 0; i < numUploaders; i++ {
			tasks <- nil
		}
		errors <- nil
	}()
	for i := 0; i < numUploaders+1; i++ {
		err := <-errors
		if err != nil {
			return err
		}
	}
	return nil
}

func (ctx *ExecContext) AbsPath(p string) string {
	// Rewrite home-relative paths as simply relative paths, which
	// we resolve in the next step relative to $HOME
	if p == "~" {
		p = ""
	}
	if len(p) >= 2 && p[:2] == "~/" {
		p = p[2:]
	}
	if !path.IsAbs(p) {
		p = path.Join([]string{ctx.env["HOME"], p}...)
	}
	return path.Clean(p)
}

func (ctx *ExecContext) Mkdirp(p string) (err error) {
	if ctx.IsWindows() {
		return errors.New("Not implemented")
	}
	_, err = ctx.Output("mkdir", "-p", ctx.AbsPath(p))
	return err
}

func (ctx *ExecContext) Stat(p string) (os.FileInfo, error) {
	flagStr := "-c"
	formatStr := "%F,%f,%s,%Y"
	if ctx.IsDarwin() {
		flagStr = "-f"
		formatStr = "%HT,%Xp,%z,%m"
	}
	p = ctx.AbsPath(p)
	stdout, _, retCode, err := ctx.Run("stat", flagStr, formatStr, p)
	// log.Printf("stat %s -- %s\n", p, strings.TrimSpace(string(stdout)))
	if err != nil {
		return nil, err
	}
	if retCode == 1 {
		return nil, NotFoundError
	}
	if retCode != 0 {
		return nil, errors.New(fmt.Sprintf("stat returned unexpected code %d", retCode))
	}
	fileInfo, err := NewFileInfoIsh(p, string(stdout))
	if err != nil {
		return nil, err
	}
	return fileInfo, nil
}

func (ctx *ExecContext) PathExists(path string) (bool, error) {
	stat, err := ctx.Stat(ctx.AbsPath(path))
	if err == NotFoundError {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return stat != nil, nil
}

func (ctx *ExecContext) ListDirectory(path string) (files []string, err error) {
	out, err := ctx.Output("ls", "-A", ctx.AbsPath(path))
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return []string{}, nil
	}
	return strings.Split(out, "\n"), nil
}

func (ctx *ExecContext) WriteFile(p string, b []byte) (err error) {
	stdinChan := make(chan io.WriteCloser, 1)
	errChan := make(chan error, 1)
	go func() {
		stdin := <-stdinChan
		for len(b) > 0 {
			nn, err := stdin.Write(b)
			b = b[nn:]
			if err != nil {
				errChan <- err
				return
			}
		}
		stdin.Close()
		errChan <- nil
	}()
	_, err = ctx.ExecSession(SessionPipeStdin(stdinChan), SessionArgs("dd", "of="+p))
	if err != nil {
		return err
	}
	err = <-errChan
	return err
}

func (ctx *ExecContext) ReadFile(p string) (b []byte, err error) {
	b, _, _, err = ctx.Run("cat", ctx.AbsPath(p))
	return b, err
}

func (ctx *ExecContext) Symlink(dest string, src string) (err error) {
	_, _, retCode, err := ctx.Run("ln", "-s", ctx.AbsPath(dest), ctx.AbsPath(src))
	if err != nil {
		return err
	}
	if retCode != 0 {
		return errors.New("Error creating symlink")
	}
	return nil
}

func (ctx *ExecContext) DeleteFile(p string) (err error) {
	_, _, retCode, err := ctx.Run("rm", ctx.AbsPath(p))
	if err != nil {
		return err
	}
	if retCode != 0 {
		return errors.New("Error deleting file")
	}
	return nil
}

func (ctx *ExecContext) DeleteLink(p string) (err error) {
	return ctx.DeleteFile(p)
}

func (ctx *ExecContext) Close() {
	ctx.lock()
	defer ctx.unlock()
	ctx.close()
}

func (ctx *ExecContext) Uname() string {
	ctx.lock()
	defer ctx.unlock()
	err := ctx.assertHasConnected()
	if err != nil {
		ctx.logger.Bail(err)
	}
	return ctx.uname
}

func (ctx *ExecContext) IsLocal() bool {
	return ctx.Hostname() == ""
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
