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
	fs.StringVar(&opts.usersd, "users", "", "Directory with user scripts (in *.txt)")
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

// attackOpts aggregates the attack function command options
type usersOpts struct {
	usersd    string
	outputf   string
	certf     string
	timeout   time.Duration
	redirects int
	laddr     localAddr
	keepalive bool
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

	var users []*vegeta.User
	for _, userFile := range userFiles {
		reader, err := file(userFile, false)
		if err != nil {
			return fmt.Errorf("error reading user file %s: %s", userFile, err)
		}
		users = append(users, vegeta.NewUser(userFile, reader, userOptions))
	}

	var wg sync.WaitGroup
	var results = make(chan *vegeta.Result)
	for _, user := range users {
		wg.Add(1)
		go func(user *vegeta.User) {
			user.Run(results)
			defer wg.Done()
		}(user)
	}

	var done = make(chan struct{}, 1)
	go func() {
		wg.Wait()
		close(done)
	}()

	enc := gob.NewEncoder(out)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	for {
		select {
		case <-sig:
			for _, user := range users {
				user.Stop()
			}
			return nil
		case r, ok := <-results:
			if !ok {
				return nil
			}
			if err = enc.Encode(r); err != nil {
				return err
			}
		case <-done:
			return nil
		}
	}

	return nil
}
