package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/tsenart/vegeta/lib"
)

func usersCmd() command {
	fs := flag.NewFlagSet("vegeta users", flag.ExitOnError)

	opts := &usersOpts{
		laddr: localAddr{&vegeta.DefaultLocalAddr},
	}
	fs.StringVar(&opts.usersd, "users", "", "Directory with user scripts, each one with .txt extension")
	fs.StringVar(&opts.outputf, "output", "stdout", "Output file")
	fs.StringVar(&opts.certf, "cert", "", "x509 Certificate file")
	fs.IntVar(&opts.redirects, "redirects", vegeta.DefaultRedirects, "Number of redirects to follow")
	fs.Var(&opts.laddr, "laddr", "Local IP address")
	fs.BoolVar(&opts.keepalive, "keepalive", true, "Use persistent connections")
	return command{fs, func(args []string) error {
		fs.Parse(args)
		return users(opts)
	}}
}

type usersOpts struct {
	certf     string
	keepalive bool
	laddr     localAddr
	outputf   string
	redirects int
	timeout   time.Duration
	usersd    string
}

func users(opts *usersOpts) error {
	var (
		err       error
		userFiles []string
	)
	tlsc := *vegeta.DefaultTLSConfig
	if opts.certf != "" {
		var cert []byte
		if cert, err = ioutil.ReadFile(opts.certf); err != nil {
			return fmt.Errorf("error reading %s: %s", opts.certf, err)
		}
		if opts.certf != "" {
			if tlsc.RootCAs, err = certPool(cert); err != nil {
				return err
			}
		}
	}

	out, err := file(opts.outputf, true)
	if err != nil {
		return fmt.Errorf("error opening %s: %s", opts.outputf, err)
	}
	defer out.Close()

	userOptions := []func(*vegeta.Attacker){
		vegeta.Redirects(opts.redirects),
		vegeta.Timeout(opts.timeout),
		vegeta.LocalAddr(*opts.laddr.IPAddr),
		vegeta.TLSConfig(&tlsc),
		vegeta.KeepAlive(opts.keepalive),
	}

	userPattern := fmt.Sprintf("%s/*.txt", opts.usersd)
	if userFiles, err = filepath.Glob(userPattern); err != nil {
		return fmt.Errorf("error reading user files %s: %s", opts.usersd, err)
	}

	fmt.Fprintf(os.Stderr, "Found %d files with scripts\n", len(userFiles))

	var users []*vegeta.User
	for _, userFile := range userFiles {
		reader, err := file(userFile, false)
		if err != nil {
			return fmt.Errorf("error reading user file %s: %s", userFile, err)
		}
		users = append(users, vegeta.NewUser(userFile, reader, userOptions))
	}

	fmt.Fprintf(os.Stderr, "Created %d user objects\n", len(users))

	var wg sync.WaitGroup

	// for now we're just streaming all the results to one place; maybe later we
	// can attach a session or something to pull them apart later? (For example,
	// you might want to find the sessions with the highest variance and do
	// reporting on them...)
	var results = make(chan *vegeta.Result)
	for idx, user := range users {
		wg.Add(1)
		fmt.Fprintf(os.Stderr, "Firing goroutine for user %d: %s\n", idx, user.Name)
		go func(user *vegeta.User) {
			user.Run(results)
			defer wg.Done()
		}(user)
	}

	var done = make(chan os.Signal, 1)
	go func() {
		fmt.Fprintln(os.Stderr, "Waiting on user wait group...")
		wg.Wait()
		done <- os.Interrupt
	}()

	enc := gob.NewEncoder(out)
	signal.Notify(done, os.Interrupt)

	// TODO: add a timeout clause?
	for {
		select {
		case r, ok := <-results:
			if !ok {
				return nil
			}
			fmt.Fprintln(os.Stderr, "Encoding result...")
			if err = enc.Encode(r); err != nil {
				return err
			}
		case <-done:
			for _, user := range users {
				user.Stop()
			}
			return nil
		}
	}

	return nil
}
