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
	return &User{
		Name:     name,
		attacker: NewAttacker(opts...),
		scanner:  peekingScanner{src: bufio.NewScanner(in)},
		stopper:  make(chan struct{}),
	}
}

func (user *User) Run(results chan<- *Result) {
	go user.createTargeters(results)
	select {
	case <-user.stopper:
		return
	}
}

func (user *User) Stop() {
	user.stopper <- struct{}{}
}

var (
	customCommand  = regexp.MustCompile("^=>")
	commentCommand = regexp.MustCompile("^//")
)

// Given a file with:
//   GET /foo/bar
//   Header:Value
//   // this is a comment
//   POST /foo/bar/baz
//   Header:Value
//   Header-Two:Value
//   @path/to/body
//
//   => PAUSE 12345
//
// Generate an array:
// [
//   "GET /foo/bar\nHeader:Value",
//   "POST /foo/bar/baz\nHeader:Value\nHeader-Two:Value\n@path/to/body",
//   "=> PAUSE 12345"
// ]
func ScanTargetsToChunks(sc peekingScanner) []string {
	var targets []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || commentCommand.MatchString(line) {
			continue
		}
		current := []string{line}
		for {
			next := sc.Peek()
			if next == "" || commentCommand.MatchString(next) {
				sc.Text() // gobble it up
				break
			} else if customCommand.MatchString(next) || httpMethod.MatchString(next) {
				break
			} else {
				sc.Scan()
				current = append(current, sc.Text())
			}
		}
		targets = append(targets, strings.Join(current, "\n"))
	}
	return targets
}

var pauseChecker = regexp.MustCompile("^=> PAUSE (\\d+)$")
var emptyBody []byte
var emptyHeaders http.Header

func (user *User) createTargeters(results chan<- *Result) {
	textTargets := ScanTargetsToChunks(user.scanner)
	fmt.Fprintf(os.Stderr, "%s: Chunked file into %d targets\n", user.Name, len(textTargets))
	for idx, chunk := range textTargets {
		label := fmt.Sprintf("%s (%d/%d)", user.Name, idx, len(textTargets))
		if matches := pauseChecker.FindStringSubmatch(chunk); matches != nil {
			millis, err := strconv.Atoi(matches[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: ERROR, bad PAUSE target %s\n", label, chunk)
				return
			}
			fmt.Fprintf(os.Stderr, "%s: Sleeping for %d ms...\n", label, millis)
			select {
			case <-user.stopper:
				return
			case <-time.After(time.Duration(millis) * time.Millisecond):
			}
			fmt.Fprintf(os.Stderr, "%s: ...DONE sleeping\n", label)
		} else {
			targeter := func() (*Target, error) {
				scanner := peekingScanner{src: bufio.NewScanner(strings.NewReader(chunk))}
				return TargetFromScanner(scanner, emptyBody, emptyHeaders, user.Name)
			}
			timestamp := time.Now()
			results <- user.attacker.hit(targeter, timestamp)
		}
		select {
		case <-user.stopper:
			break
		case <-time.After(2 * time.Second):
		}
	}
}
