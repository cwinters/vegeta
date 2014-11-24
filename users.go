package main

import (
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

	for _, user := range users {
		wg.Add(1)
		go func(user *vegeta.User) {
			defer wg.Done()
			user.Run()
		}(user)
	}

	// catch completion of all users, and from the OS
	var done = make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt)
	go func() {
		wg.Wait()
		done <- os.Interrupt
	}()

	for {
		select {
		case <-done:
			for _, user := range users {
				user.Stop() // wait for each user to finish up?
			}
			return nil
		}
	}

	return nil
}
