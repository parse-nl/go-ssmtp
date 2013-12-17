package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"os/user"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var config = &Configuration{
	ConfigFile:	"/etc/go-ssmtp.ini",
	Port:		25,
	Postmaster:	"postmaster",
	Verbose:	false,
}

type Configuration struct {
	ConfigFile						string
	Verbose							bool
	Hostname						string
	Server							string
	Port							int
	Postmaster						string
	Authentication_User				string
	Authentication_Password			string
	Authentication_Identity			string
	Authentication_Mechanism		string
	Authentication_ForceStartTLS	bool
	Message_To						[]string
	Message_From					string
	Message_FromName				string
	Message_Bcc						string
}

func generateMessageId() string {
	const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes, i, r := make([]byte, 16), 0, rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		bytes[i] = CHARS[r.Intn(len(CHARS))]
		i++

		if i == len(bytes) {
			return string(bytes)
		}
	}
}

func (c *Configuration) ParseFile(file string) error {
	var matchSection = regexp.MustCompile(`^\[([^]]+)\]$`)
	var matchPair = regexp.MustCompile(`^([^#;=]+)=(.*)$`)

	f, err := os.Open(file)

	if err != nil {
		return err
	}

	defer f.Close()

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	var n, section = 1, ""

	for s.Scan() {
		l := s.Text()

		if 0 == len(l) || ';' == l[0] {
			continue
		} else if parts := matchSection.FindStringSubmatch(l); parts != nil {
			section = parts[1]
		} else if parts := matchPair.FindStringSubmatch(l); parts != nil {
			k, v := parts[1], parts[2]

			if section != "" {
				k = section + "_" + k
			}

			if !c.Get(k).IsValid() {
				fmt.Fprintf(os.Stderr, "Warning: unknown configuration variable %s, line %d\n", k, n)
			} else if "string" == config.Get(k).Type().String() {
				c.Get(k).SetString(v)
			} else if "bool" == config.Get(k).Type().String() {
				c.Get(k).SetBool("1" == v)
			}
		} else {
			return fmt.Errorf("Failed to parse config, line %d: %s", n, l)
		}

		n++
	}

	return nil
}

func (c *Configuration) Get(k string) reflect.Value {
	r := reflect.ValueOf(c)
	return reflect.Indirect(r).FieldByName(k)
}

func init() {
	if h, err := os.Hostname(); err == nil {
		config.Hostname = h
	} else {
		config.Hostname = "localhost"
	}

	if u, err := user.Current(); err == nil {
		config.Message_From = u.Username + "@" + config.Hostname

		if u.Name != "" {
			config.Message_FromName = u.Name
		} else {
			config.Message_FromName = u.Username
		}
	}

	if -1 == strings.Index(config.Postmaster, "@") {
		config.Postmaster += "@" + config.Hostname
	}

	flag.BoolVar(&config.Verbose, "v", config.Verbose, "Enable verbose mode")
	flag.StringVar(&config.ConfigFile, "C", config.ConfigFile, "Use alternate configuration file")
	flag.StringVar(&config.Message_From, "f", config.Message_From, "Manually specify the sender-address of the email")
	flag.StringVar(&config.Message_FromName, "F", config.Message_FromName, "Manually specify the sender-name of the email")
}

func compose() string {
	// Make sure we can re-use Stdin even after being consumed
	b := bytes.Buffer{}
	b.ReadFrom(os.Stdin)
	msg := b.String()
	r := bytes.NewBufferString(msg)

	m, err := mail.ReadMessage(r)
	if err != nil {
		// Assume there are no headers in the message
		m = &mail.Message{
			Header: mail.Header(textproto.MIMEHeader{}),
			Body:   bufio.NewReader(bytes.NewBufferString(msg)),
		}
	}

	if 0 == len(m.Header["From"]) {
		m.Header["From"] = []string{(&mail.Address{config.Message_FromName, config.Message_From}).String()}
	}

	if 0 == len(m.Header["To"]) {
		m.Header["To"] = config.Message_To
	}

	if 0 == len(m.Header["Date"]) {
		m.Header["Date"] = []string{time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700")}
	}

	if 0 == len(m.Header["Message-ID"]) {
		m.Header["Message-Id"] = []string{"<GOSSMTP." + generateMessageId() + "@" + config.Hostname + ">"}
	}

	var s = ""
	for k, h := range m.Header {
		for _, v := range h {
			s += k + ": " + v + "\r\n"
		}
	}

	c := bytes.Buffer{}
	c.ReadFrom(m.Body)

	return s + "\r\n" + c.String()
}

func send(msg string) error {
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", config.Server, config.Port))

	if err != nil {
		return fmt.Errorf("while connecting to %s on port %s: %s", config.Server, config.Port, err)
	}

	if err := c.Hello(config.Hostname); err != nil {
		return fmt.Errorf("while sending Hello `%s`: %s", config.Hostname, err)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(nil); err != nil {
			return fmt.Errorf("while enabling startTLS: %s", err)
		}
	} else if config.Authentication_ForceStartTLS {
		return fmt.Errorf("server does not support StartTLS")
	}

	switch config.Authentication_Mechanism {
	case "CRAM-MD5":
		auth := smtp.CRAMMD5Auth(
			config.Authentication_User,
			config.Authentication_Password,
		)

		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				return fmt.Errorf("while authenticating: %s", err)
			} else if config.Verbose {
				return fmt.Errorf("Info: using authentication: CRAM-MD5")
			}
		}

	case "PLAIN":
		auth := smtp.PlainAuth(
			config.Authentication_Identity,
			config.Authentication_User,
			config.Authentication_Password,
			config.Server,
		)

		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				return fmt.Errorf("while authenticating: %s", err)
			} else if config.Verbose {
				fmt.Println("Info: using authentication: PLAIN")
			}
		}

	default:
		if config.Verbose {
			fmt.Println("Info: not using authentication")
		}
	}

	if err = c.Mail(config.Message_From); err != nil {
		return fmt.Errorf("while setting From `%s`: %s", config.Message_From, err)
	}

	if config.Message_Bcc != "" {
		if err = c.Rcpt(config.Message_Bcc); err != nil {
			return fmt.Errorf("while setting Bcc `%s`: %s", config.Message_Bcc, err)
		}
	}

	for _, to := range config.Message_To {
		if err = c.Rcpt(to); err != nil {
			return fmt.Errorf("while setting To `%s`: %s", config.Message_To, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("while setting Data: %s", err)
	}

	if _, err = w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("while sending message: %s", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("while closing message: %s", err)
	}

	if err = c.Quit(); err != nil {
		return fmt.Errorf("while closing connection: %s", err)
	}

	return nil
}

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Error: no recipients supplied")
		os.Exit(1)
	}

	// Map all local users to Postmaster address
	config.Message_To = flag.Args()
	for i, to := range config.Message_To {
		if -1 == strings.Index(to, "@") {
			config.Message_To[i] = config.Postmaster
		}
	}

	if err := config.ParseFile(config.ConfigFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing configuration: %s\n", err)
		os.Exit(2)
	}

	if config.Verbose {
		fmt.Printf("%#v\n", *config)
	}

	msg := compose()

	if err := send(msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(3)
	} else if config.Verbose {
		fmt.Println("Info: send successful")
	}
}
