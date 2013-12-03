package main

import (
	"flag"
	"fmt"
	"net/smtp"
	"net/textproto"
	"net/mail"
	"time"
	"bufio"
	"os"
	"os/user"
	"regexp"
	"crypto/rand"
	"bytes"
	"reflect"
)

var config = &Configuration{
	ConfigFile: "/etc/go-ssmtp.conf",
	Port: 25,
	Postmaster: "postmaster",
	Verbose: false,
}

type Configuration struct{
	ConfigFile string
	Verbose bool
	Hostname  string
	Server string
	Port int
	Postmaster string
	Authentication_User string
	Authentication_Password string
	Authentication_Identity string
	Authentication_Mechanism string
	Authentication_ForceStartTLS bool
	Message_To []string
	Message_From string
	Message_FromName string
	Message_Bcc string
}

func generateMessageId() string {
	const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, 16)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = CHARS[b % byte(len(CHARS))]
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
				k = section +"_"+ k
			}

			if !c.Get(k).IsValid() {
				fmt.Fprintf(os.Stderr, "Warning: unknown configuration variable %s, line %d\n", k, n)
			} else if "string" == config.Get(k).Type().String() {
				c.Get(k).SetString(v)
			} else if "bool" == config.Get(k).Type().String() {
				c.Get(k).SetBool("1"==v)
			}
		} else {
			return fmt.Errorf("Failed to parse config, line %d: %s", n, l)
		}

		n++
	}

	return nil
}

func (c *Configuration) Get(k string) reflect.Value{
	r := reflect.ValueOf(c)
	return reflect.Indirect(r).FieldByName(k)
}

func init() {
	if h, err := os.Hostname(); err == nil {
		config.Hostname = h
	} else {
		config.Hostname = "localhost"
	}

	var defaultFrom, defaultName = "", ""
	if u, err := user.Current(); err == nil {
		defaultFrom = u.Username +"@"+ config.Hostname

		if u.Name != "" {
			defaultName = u.Name
		} else {
			defaultName = u.Username
		}
	}

	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose mode")
	flag.StringVar(&config.Authentication_Mechanism, "am", "", "Mechanism for SMTP authentication")
	flag.StringVar(&config.Authentication_User, "au", "", "Username for SMTP authentication")
	flag.StringVar(&config.Authentication_Password, "ap", "", "Password for SMTP authentication")
	flag.StringVar(&config.ConfigFile, "C", "", "Use alternate configuration file")
	flag.StringVar(&config.Message_From, "f", defaultFrom, "Manually specify the sender-address of the email")
	flag.StringVar(&config.Message_FromName, "F", defaultName, "Manually specify the sender-name of the email")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Error: no recipients supplied")
		os.Exit(1)
	} else {
		config.Message_To = flag.Args()
	}
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
			Body: bufio.NewReader(bytes.NewBufferString(msg)),
		}
	}

	if 0 == len(m.Header["From"]) {
		m.Header["From"] = []string{(&mail.Address{config.Message_FromName, config.Message_From}).String()}
	}

	if 0 == len(m.Header["To"]) {
		m.Header["To"] = config.Message_To
	}

	if 0 == len(m.Header["Date"]) {
		m.Header["Date"] = []string{time.Now().String()}
	}

	if 0 == len(m.Header["Message-ID"]) {
		m.Header["Message-Id"] = []string{ "<GOSSMTP."+ generateMessageId() +"@"+ config.Hostname +">"}
	}

	var s = ""
	for k, h := range m.Header {
		for _, v := range h {
			s += k +": "+ v +"\r\n"
		}
	}

	c := bytes.Buffer{}
	c.ReadFrom(m.Body)

	return s + "\r\n"+ c.String()
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
	if err := config.ParseFile(config.ConfigFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing configuration: %s\n", err)
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Printf("%#v\n", *config)
	}

	msg := compose()

	if err := send(msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	} else if config.Verbose {
		fmt.Println("Info: send successful")
	}
}