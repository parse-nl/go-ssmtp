package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/blackjack/syslog"
	"math/rand"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"os/user"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var config = &Configuration{
	Verbose:         false,
	ConfigFile:      "/etc/go-ssmtp.ini",
	Port:            25,
	Server:          "127.0.0.1",
	Postmaster:      "postmaster",
	ScanMessage:     false,
	Message_Subject: "(no subject)",
}

type Configuration struct {
	Verbose                           bool
	ConfigFile                        string
	Hostname                          string
	Server                            string
	Port                              int
	Postmaster                        string
	ScanMessage                       bool
	Authentication_User               string
	Authentication_Password           string
	Authentication_Identity           string
	Authentication_Mechanism          string
	Authentication_ForceStartTLS      bool
	Authentication_InsecureSkipVerify bool
	Message_To                        []string
	Message_From                      string
	Message_FromName                  string
	Message_Subject                   string
	Message_FromCronDaemon            bool
}

func generateMessageId() string {
	const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, 16)

	for i, r := 0, rand.New(rand.NewSource(time.Now().UnixNano())); i < len(bytes); i++ {
		bytes[i] = CHARS[r.Intn(len(CHARS))]
	}

	return string(bytes)
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
			} else if "int" == config.Get(k).Type().String() {
				if i, err := strconv.ParseInt(v, 10, 64); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not parse value `%s` for %s, line %d\n", v, k, n)
				} else {
					c.Get(k).SetInt(i)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Warning: unsupported type %v for %s\n", config.Get(k).Type(), k)
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

func compose() (*mail.Message, error) {
	// Make sure we can re-use Stdin even after being consumed by mail.ReadMessage
	b := bytes.Buffer{}
	b.ReadFrom(os.Stdin)
	msg := b.String()

	m, err := mail.ReadMessage(bytes.NewBufferString(msg))
	if err != nil {
		if config.ScanMessage {
			return nil, fmt.Errorf("ScanMessage: cannot parse message: %s", err)
		}

		// Assume there are no headers in the message
		m = &mail.Message{
			Header: mail.Header(textproto.MIMEHeader{}),
			Body:   bufio.NewReader(bytes.NewBufferString(msg)),
		}
	}

	// Make sure all required fields are set
	if 0 == len(m.Header["From"]) {
		m.Header["From"] = []string{(&mail.Address{
			Name:    config.Message_FromName,
			Address: config.Message_From,
		}).String()}
	} else if from, err := mail.ParseAddress(m.Header["From"][0]); config.ScanMessage && err == nil {
		// Parse and put in config; to be used by c.Mail
		config.Message_From = from.Address
	}

	if 0 == len(m.Header["To"]) {
		m.Header["To"] = config.Message_To
	}

	if 0 == len(m.Header["Date"]) {
		m.Header["Date"] = []string{time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700")}
	}

	if 0 == len(m.Header["Message-Id"]) {
		m.Header["Message-Id"] = []string{"<GOSSMTP." + generateMessageId() + "@" + config.Hostname + ">"}
	}

	if 0 == len(m.Header["Subject"]) {
		m.Header["Subject"] = []string{config.Message_Subject}
	}

	return m, nil
}

func connect() (*smtp.Client, error) {
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", config.Server, config.Port))

	if err != nil {
		return nil, fmt.Errorf("while connecting to %s on port %d: %s", config.Server, config.Port, err)
	}

	if err := c.Hello(config.Hostname); err != nil {
		return nil, fmt.Errorf("while sending Hello `%s`: %s", config.Hostname, err)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: config.Server, InsecureSkipVerify: config.Authentication_InsecureSkipVerify}); err != nil {
			return nil, fmt.Errorf("while enabling StartTLS: %s", err)
		}
	} else if config.Authentication_ForceStartTLS {
		return nil, fmt.Errorf("server does not support StartTLS")
	}

	switch config.Authentication_Mechanism {
	case "CRAM-MD5":
		auth := smtp.CRAMMD5Auth(
			config.Authentication_User,
			config.Authentication_Password,
		)

		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				return nil, fmt.Errorf("while authenticating: %s", err)
			} else if config.Verbose {
				return nil, fmt.Errorf("Info: using authentication: CRAM-MD5")
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
				return nil, fmt.Errorf("while authenticating: %s", err)
			} else if config.Verbose {
				fmt.Println("Info: using authentication: PLAIN")
			}
		}

	default:
		if config.Verbose {
			fmt.Println("Info: not using authentication")
		}
	}

	return c, nil
}

func send(c *smtp.Client, m *mail.Message) error {
	if err := c.Mail(config.Message_From); err != nil {
		return fmt.Errorf("while setting From `%s`: %s", config.Message_From, err)
	}

	if config.ScanMessage {
		for _, i := range []string{"To", "Cc", "Bcc"} {
			if 0 == len(m.Header[i]) {
				continue
			}

			if l, err := m.Header.AddressList(i); err != nil {
				fmt.Fprintf(os.Stderr, "ScanMessage: Could not parse recipients in %s `%s`; %s", i, l, err)
			} else {
				for _, v := range l {
					config.Message_To = append(config.Message_To, v.Address)
				}
			}
		}

		if 0 == len(config.Message_To) {
			fmt.Fprintln(os.Stderr, "ScanMessage: No recipients found in message-body")
		}
	}

	for _, to := range config.Message_To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("while setting Recipient `%s`: %s", to, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("while setting Data: %s", err)
	}

	var s = ""
	for k, h := range m.Header {
		for _, v := range h {
			s += k + ": " + v + "\r\n"
		}
	}

	b := bytes.Buffer{}
	b.ReadFrom(m.Body)

	if _, err := w.Write([]byte(s + "\r\n" + b.String())); err != nil {
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

	syslog.Openlog("go-ssmtp", syslog.LOG_PID, syslog.LOG_USER)

	// rewrite os.Args so we can parse -FFrom > -F From
	newArgs := []string{os.Args[0]}
	for _, arg := range os.Args[1:] {
		if len(arg) > 2 && arg[0] == '-' {
			newArgs = append(newArgs, arg[0:2], arg[2:])
		} else {
			newArgs = append(newArgs, arg)
		}
	}
	os.Args = newArgs

	var ignoreBool bool
	var ignoreString string
	flag.BoolVar(&ignoreBool, "i", false, "Ignore dots alone on lines - ignored")
	flag.StringVar(&ignoreString, "o", "", "Set option x to the specified - ignored")
	flag.BoolVar(&config.Verbose, "v", config.Verbose, "Enable verbose mode")
	flag.StringVar(&config.ConfigFile, "C", config.ConfigFile, "Use alternate configuration file")
	flag.StringVar(&config.Message_From, "f", config.Message_From, "Manually specify the sender-address of the email")
	flag.StringVar(&config.Message_FromName, "F", config.Message_FromName, "Manually specify the sender-name of the email")
	flag.StringVar(&config.Message_Subject, "S", config.Message_Subject, "Manually specify the subject of the email")
	flag.BoolVar(&config.ScanMessage, "t", config.ScanMessage, "Scan message for recipients")
}

func main() {
	flag.Parse()

	if config.Message_FromCronDaemon {
		config.Message_FromName = "CronDaemon"
	}

	if err := config.ParseFile(config.ConfigFile); err != nil {
		panic("error: parsing configuration: " + err.Error())
	}

	// Map all local users to Postmaster address
	config.Message_To = flag.Args()
	for i, to := range config.Message_To {
		if -1 == strings.Index(to, "@") {
			config.Message_To[i] = config.Postmaster
		}
	}

	if config.Verbose {
		fmt.Printf("%#v\n", *config)
	}

	if len(config.Message_To) == 0 && !config.ScanMessage {
		panic("error: no recipients supplied")
	}

	if m, err := compose(); err != nil {
		syslog.Errf("compose: %s", err)
		panic("compose: " + err.Error())
	} else if c, err := connect(); err != nil {
		syslog.Errf("connect: %s", err)
		panic("connect: " + err.Error())
	} else if err := send(c, m); err != nil {
		syslog.Errf("send: %s", err)
		panic("send: " + err.Error())
	} else {
		syslog.Syslogf(syslog.LOG_INFO, "[%s] Sent mail; subject \"%s\"; from %s; to %#v", m.Header["Message-Id"][0], m.Header["Subject"][0], config.Message_From, config.Message_To)
	}

	if config.Verbose {
		fmt.Println("Info: send successful")
	}
}
