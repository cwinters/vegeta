package vegeta

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
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
	running  bool
}

func NewUser(name string, in io.Reader, opts []func(*Attacker)) *User {
	return &User{
		Name:     name,
		attacker: NewAttacker(opts...),
		scanner:  peekingScanner{src: bufio.NewScanner(in)},
		stopper:  make(chan struct{}),
	}
}

type UserEncoder struct {
	Name        string
	encoderFile io.WriteCloser
	encoder     *gob.Encoder
}

func NewUserEncoder(name string) *UserEncoder {
	encoderDir := path.Dir(name)
	encoderName := strings.Replace(path.Base(name), ".txt", ".bin", -1)
	encoderFullPath := path.Join(encoderDir, encoderName)
	if encoderFile, err := os.Create(encoderFullPath); err != nil {
		panic(fmt.Sprintf("Cannot create encoder for results [Path: %s] [User file: %s] => %s", encoderFullPath, name, err))
	} else {
		encoder := gob.NewEncoder(encoderFile)
		return &UserEncoder{encoderName, encoderFile, encoder}
	}
}

func (e *UserEncoder) AddResult(r *Result) error {
	return e.encoder.Encode(r)
}

func (e *UserEncoder) Close() {
	e.encoderFile.Close()
}

func (user *User) Run() {
	user.running = true
	enc := NewUserEncoder(user.Name)
	results := make(chan *Result)
	go user.process(results)
	for {
		select {
		case result := <-results:
			enc.AddResult(result)

		// wait for the next result (or timeout) then wrap up:
		case <-user.stopper:
			user.running = false
			fmt.Fprintf(os.Stderr, "%s: All done or asked to stop, waiting for next result or 5 seconds...\n", user.Name)
			select {
			case result := <-results:
				enc.AddResult(result)
			case <-time.After(5 * time.Second):
			}
			enc.Close()
			fmt.Fprintf(os.Stderr, "%s: ...DONE\n", user.Name)
			return
		}
	}
}

func (user *User) Stop() {
	if user.running {
		user.stopper <- struct{}{}
	}
}

var (
	customCommand  = regexp.MustCompile("^=>")
	commentCommand = regexp.MustCompile("^//")
)

func ScanFileToChunks(reader io.Reader) []string {
	return ScanTargetsToChunks(peekingScanner{src: bufio.NewScanner(reader)})
}

func ScanFileToTargets(reader io.Reader) []*Target {
	var targets []*Target
	for idx, chunk := range ScanFileToChunks(reader) {
		if !strings.Contains(chunk, "=> ") {
			scanner := peekingScanner{src: bufio.NewScanner(strings.NewReader(chunk))}
			target, err := TargetFromScanner(scanner, emptyBody, emptyHeaders, "Reader")
			if err != nil {
				panic(fmt.Errorf("Error reading item %d => %s\n%s", idx, err, chunk))
			}
			targets = append(targets, target)
		}
	}
	return targets
}

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
				sc.Text() // gobble it up and leave
				break
			} else if customCommand.MatchString(next) || httpMethod.MatchString(next) {
				break // leave but keep the scanner at the line
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

func (user *User) process(results chan *Result) {
	textTargets := ScanTargetsToChunks(user.scanner)
	for idx, chunk := range textTargets {
		label := fmt.Sprintf("%s (%d/%d)", user.Name, idx, len(textTargets))
		if matches := pauseChecker.FindStringSubmatch(chunk); matches != nil {
			millis, err := strconv.Atoi(matches[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: ERROR, bad PAUSE target %s\n", label, chunk)
				return
			}
			fmt.Fprintf(os.Stderr, "%s: Sleeping (%d ms)...\n", label, millis)
			select {
			case <-user.stopper:
				return
			case <-time.After(time.Duration(millis) * time.Millisecond):
			}
		} else {
			targeter := func() (*Target, error) {
				scanner := peekingScanner{src: bufio.NewScanner(strings.NewReader(chunk))}
				return TargetFromScanner(scanner, emptyBody, emptyHeaders, user.Name)
			}
			timestamp := time.Now()
			result := user.attacker.hit(targeter, timestamp)
			fmt.Fprintf(os.Stderr, "%s: %s %s, %d ms\n",
				label, result.Method, result.URL, int64(result.Latency/time.Millisecond))
			results <- result
		}
	}
	user.stopper <- struct{}{}
}
