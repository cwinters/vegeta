package vegeta

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type timedTargeter struct {
	Targeter  Targeter
	Timestamp time.Time
}

type User struct {
	Name     string
	attacker *Attacker
	scanner  peekingScanner
	stopper  chan struct{}
}

func NewUser(name string, in io.Reader, opts []func(*Attacker)) *User {
	attacker := NewAttacker(opts...)
	scanner := peekingScanner{src: bufio.NewScanner(in)}
	return &User{name, attacker, scanner, make(chan struct{})}
}

var pauseChecker = regexp.MustCompile("^PAUSE")
var emptyBody []byte
var emptyHeaders http.Header

func (user *User) Run(results chan<- *Result) {
	targeters := make(chan timedTargeter)
	go user.createTargeters(targeters)
	var targeter timedTargeter
	select {
	case targeter = <-targeters:
		results <- user.attacker.hit(targeter.Targeter, targeter.Timestamp)
	case <-user.stopper:
		close(targeters)
		return
	}
}

func (user *User) Stop() {
	user.stopper <- struct{}{}
}

func (user *User) createTargeters(targeters chan<- timedTargeter) {
	if !user.scanner.Scan() {
		return
	}
	if pauseChecker.MatchString(user.scanner.Peek()) {
		line := user.scanner.Text()
		tokens := strings.SplitN(line, " ", 2)
		if len(tokens) < 2 {
			fmt.Fprintf(os.Stderr, "%s: ERROR, bad PAUSE target %s", user.Name, line)
			return
		}
		millis, err := strconv.Atoi(tokens[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: ERROR, bad PAUSE target %s", user.Name, line)
			return
		}
		fmt.Fprintf(os.Stderr, "%s: Sleeping for %d ms...\n", user.Name, millis)
		time.Sleep(time.Duration(millis) * time.Millisecond)
		fmt.Fprintf(os.Stderr, "%s: ...DONE sleeping\n", user.Name)

		// prime the scanner with the next actual line
		user.scanner.Scan()
		if user.scanner.Text() == "" {
			user.scanner.Scan()
		}
	}

	timestamp := time.Now()
	targeter := func() (*Target, error) {
		return TargetFromScanner(user.scanner, emptyBody, emptyHeaders)
	}
	targeters <- timedTargeter{targeter, timestamp}
}
