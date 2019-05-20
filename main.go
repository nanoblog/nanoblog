package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/ChimeraCoder/anaconda"
	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/securecookie"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// Flags
	cli = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// datadir
	datadir string

	// The version is set by the build command.
	version string

	// backlink
	backlink string

	// show version
	showVersion bool

	// show help
	showHelp bool

	// debug logging
	debug bool

	// Let's Encrypt
	letsencrypt bool

	// HTTP read limit
	httpReadLimit int64 = 2 * (1024 * 1024)

	// securetoken
	securetoken *securecookie.SecureCookie

	// logger
	logger = log.New()

	// config
	config *Config

	// mailer
	mailer = NewMailer()

	// SAML
	samlSP *samlsp.Middleware

	// Error page HTML
	errorPageHTML = `<html><head><title>Error</title></head><body text="orangered" bgcolor="black"><h1>An error has occurred</h1></body></html>`

	// profiling
	cpuprofile string
	memprofile string

	// signals
	sigint chan os.Signal

	// httpd
	httpAddr   string
	httpHost   string
	httpPrefix string

	// Insecure http cookies (only recommended for internal LANs/VPNs)
	httpInsecure bool

	// set based on httpAddr
	httpIP   string
	httpPort string

	// twitter api
	twitterAPI *anaconda.TwitterApi

	// User uploaded images
	profileFilename string
	//bannerFilename    string

	// Timezone
	timezoneLocation *time.Location
	timezoneLock     sync.Mutex
)

func init() {
	cli.StringVar(&datadir, "datadir", "/data", "data dir")
	cli.StringVar(&backlink, "backlink", "", "backlink (optional)")
	cli.BoolVar(&showVersion, "version", false, "display version and exit")
	cli.BoolVar(&showHelp, "help", false, "display help and exit")
	cli.BoolVar(&debug, "debug", false, "debug mode")
	cli.BoolVar(&httpInsecure, "http-insecure", false, "enable sessions cookies for http (no https) not recommended")
	cli.BoolVar(&letsencrypt, "letsencrypt", true, "enable TLS using Let's Encrypt on port 443")
	cli.StringVar(&cpuprofile, "cpuprofile", "", "write cpu profile to `file`")
	cli.StringVar(&memprofile, "memprofile", "", "write mem profile to `file`")
	cli.StringVar(&httpAddr, "http-addr", ":80", "HTTP listen address")
	cli.StringVar(&httpHost, "http-host", "", "HTTP host (required)")
}

func main() {
	var err error

	cli.Parse(os.Args[1:])
	usage := func(msg string) {
		if msg != "" {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
		}
		fmt.Fprintf(os.Stderr, "Usage: %s --http-host analytics.example.com\n\n", os.Args[0])
		cli.PrintDefaults()
	}
	if showHelp {
		usage("Help info")
		os.Exit(0)
	}

	if showVersion {
		fmt.Printf("Nanoblog %s\n", version)
		os.Exit(0)
	}

	// Images
	profileFilename = filepath.Join(datadir, "profile")
	//bannerFilename = filepath.Join(datadir, "banner")

	// http host
	if httpHost == "" {
		usage("the --http-host flag is required")
		os.Exit(1)
	}

	// debug logging
	logger.Out = os.Stdout
	if debug {
		logger.SetLevel(log.DebugLevel)
	}
	logger.Debugf("debug logging is enabled")

	// http port
	httpIP, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		usage("invalid --http-addr: " + err.Error())
	}

	// Handle SIGINT
	sigint = make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	go func() {
		<-sigint
		if cpuprofile != "" {
			pprof.StopCPUProfile()
		}
		os.Exit(0)
	}()

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			logger.Fatalf("could not create CPU profile: %s", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			logger.Fatalf("could not start CPU profile: %s", err)
		}
		defer pprof.StopCPUProfile()
	}

	if memprofile != "" {
		f, err := os.Create(memprofile)
		if err != nil {
			logger.Fatalf("could not create memory profile: %s", err)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			logger.Fatalf("could not write memory profile: %s", err)
		}
		f.Close()
	}

	// config
	config, err = NewConfig("config.json")
	if err != nil {
		logger.Fatal(err)
	}
	info := config.FindInfo()

	// Set timezone.
	if err := setTimezone(info.Location); err != nil {
		logger.Warnf("failed to set timezone (apt-get install tzdata?): %s", err)
	}

	// Secure token
	securetoken = securecookie.New([]byte(info.HashKey), []byte(info.BlockKey))

	// Configure SAML if metadata is present.
	if len(config.FindInfo().SAML.IDPMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
		}
	}

	// Configure Twitter API
	updateTwitterAPI()

	// Draft manager
	go dman()

	//
	// Routes
	//
	r := &httprouter.Router{}
	r.GET("/", Log(WebHandler(indexHandler, "index")))
	r.GET("/domain", Log(WebHandler(domainHandler, "domain")))

	r.GET("/profile", WebHandler(profileHandler, "profile"))
	//r.GET("/banner", WebHandler(bannerHandler, "banner"))

	r.GET("/configure", Log(WebHandler(configureHandler, "configure")))
	r.POST("/configure", Log(WebHandler(configureHandler, "configure")))

	r.GET("/forgot", Log(WebHandler(forgotHandler, "forgot")))
	r.POST("/forgot", Log(WebHandler(forgotHandler, "forgot")))

	// SAML
	r.GET("/sso", Log(ssoHandler))
	r.GET("/saml/metadata", Log(samlHandler))
	r.POST("/saml/metadata", Log(samlHandler))
	r.GET("/saml/acs", Log(samlHandler))
	r.POST("/saml/acs", Log(samlHandler))

	r.GET("/signin", Log(WebHandler(signinHandler, "signin")))
	r.POST("/signin", Log(WebHandler(signinHandler, "signin")))

	r.GET("/signout", Log(WebHandler(signoutHandler, "signout")))
	r.GET("/help", Log(WebHandler(helpHandler, "help")))

	// Posts
	r.GET("/posts/:post", Log(WebHandler(postsViewHandler, "posts/view")))

	// Admin
	r.POST("/admin/posts/add", Log(WebHandler(postsAddHandler, "admin/posts/add")))
	r.GET("/admin/posts/delete/:post", Log(WebHandler(postsDeleteHandler, "admin/posts/delete")))
	r.GET("/admin/drafts/delete/:draft", Log(WebHandler(draftsDeleteHandler, "admin/drafts/delete")))

	r.GET("/admin", Log(WebHandler(adminIndexHandler, "admin/index")))

	// Admin settings
	r.GET("/admin/settings", Log(WebHandler(adminSettingsIndexHandler, "admin/settings/index")))
	r.POST("/admin/settings", Log(WebHandler(adminSettingsIndexHandler, "admin/settings/index")))

	r.GET("/admin/settings/menu", Log(WebHandler(adminSettingsMenuHandler, "admin/settings/menu")))
	r.POST("/admin/settings/menu", Log(WebHandler(adminSettingsMenuHandler, "admin/settings/menu")))

	r.GET("/admin/settings/sso", Log(WebHandler(adminSettingsSSOHandler, "admin/settings/sso")))
	r.POST("/admin/settings/sso", Log(WebHandler(adminSettingsSSOHandler, "admin/settings/sso")))

	r.GET("/admin/settings/api", Log(WebHandler(adminSettingsAPIHandler, "admin/settings/api")))
	r.POST("/admin/settings/api", Log(WebHandler(adminSettingsAPIHandler, "admin/settings/api")))

	r.GET("/admin/settings/snippet", Log(WebHandler(adminSettingsSnippetHandler, "admin/settings/snippet")))
	r.POST("/admin/settings/snippet", Log(WebHandler(adminSettingsSnippetHandler, "admin/settings/snippet")))

	r.GET("/admin/settings/password", Log(WebHandler(adminSettingsPasswordHandler, "admin/settings/password")))
	r.POST("/admin/settings/password", Log(WebHandler(adminSettingsPasswordHandler, "admin/settings/password")))

	r.POST("/admin/schedule", Log(WebHandler(adminScheduleHandler, "admin/schedule")))

	// Static assets
	r.GET("/static/*path", staticHandler)

	//
	// Server
	//
	httpTimeout := 1 * time.Hour
	maxHeaderBytes := 10 * (1024 * 1024) // 10 MB

	// Plain text web server for use behind a reverse proxy.
	if !letsencrypt {
		httpd := &http.Server{
			Handler:        r,
			Addr:           net.JoinHostPort(httpIP, httpPort),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		hostport := net.JoinHostPort(httpHost, httpPort)
		if httpPort == "80" {
			hostport = httpHost
		}
		logger.Infof("Nanoblog version: %s %s", version, &url.URL{
			Scheme: "http",
			Host:   hostport,
			Path:   httpPrefix,
		})
		logger.Fatal(httpd.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(datadir, "letsencrypt")),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.TrimPrefix(host, "www.")
			if host == httpHost {
				return nil
			}
			if host == config.FindInfo().Domain {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %q not permitted by HostPolicy", host)
		},
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET("/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(httpHost, httpPort)
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpd := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpd.ListenAndServe(); err != nil {
			logger.Fatalf("http server on port 80 failed: %s", err)
		}
	}()
	// TLS
	tlsConfig := tls.Config{
		GetCertificate:           certmanager.GetCertificate,
		NextProtos:               []string{"http/1.1"},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		httpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpsd := &http.Server{
		Handler:        r,
		Addr:           httpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostport := net.JoinHostPort(httpHost, httpPort)
	if httpPort == "443" {
		hostport = httpHost
	}
	logger.Infof("Nanoblog version: %s %s", version, &url.URL{
		Scheme: "https",
		Host:   hostport,
		Path:   httpPrefix + "/",
	})
	logger.Fatal(httpsd.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(10 * time.Minute)
	return tc, nil
}

// TODO: Protect this with a mutex.
func updateTwitterAPI() error {
	info := config.FindInfo()

	// Disable twitter.
	if info.Twitter.ConsumerKey == "" || info.Twitter.ConsumerSecret == "" ||
		info.Twitter.AccessToken == "" || info.Twitter.AccessTokenSecret == "" {
		config.UpdateInfo(func(i *Info) error {
			i.Twitter.ID = 0
			i.Twitter.ScreenName = ""
			return nil
		})
		twitterAPI = nil
		return nil
	}

	// Enable twitter.
	anaconda.SetConsumerKey(info.Twitter.ConsumerKey)
	anaconda.SetConsumerSecret(info.Twitter.ConsumerSecret)
	twitterAPI = anaconda.NewTwitterApi(info.Twitter.AccessToken, info.Twitter.AccessTokenSecret)

	user, err := twitterAPI.GetSelf(url.Values{})
	if err != nil {
		logger.Warnf("twitter get self failed: %s", err)
		twitterAPI = nil
		return err
	}
	config.UpdateInfo(func(i *Info) error {
		i.Twitter.ID = user.Id
		i.Twitter.ScreenName = user.ScreenName
		return nil
	})
	return nil
}

func setTimezone(name string) error {
	timezoneLock.Lock()
	defer timezoneLock.Unlock()

	location, err := time.LoadLocation(name)
	if err != nil {
		timezoneLocation = time.UTC
		return err
	}
	timezoneLocation = location
	return nil
}

func getTimezone() *time.Location {
	timezoneLock.Lock()
	defer timezoneLock.Unlock()
	return timezoneLocation
}

func configureSAML() error {
	info := config.FindInfo()

	if len(info.SAML.IDPMetadata) == 0 {
		return fmt.Errorf("no IDP metadata")
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entity)

	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entities); err != nil {
			return err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}

	keyPair, err := tls.X509KeyPair(info.SAML.Certificate, info.SAML.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SAML keypair: %s", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SAML certificate: %s", err)
	}

	rootURL := url.URL{
		Scheme: "https",
		Host:   BestDomain(),
		Path:   "/",
	}

	newsp, err := samlsp.New(samlsp.Options{
		URL:               rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       entity,
		CookieName:        SessionCookieNameSSO,
		CookieSecure:      !httpInsecure,
		Logger:            logger,
		AllowIDPInitiated: true,
	})
	if err != nil {
		logger.Warnf("failed to configure SAML: %s", err)
		samlSP = nil
		return fmt.Errorf("failed to configure SAML: %s", err)
	}
	samlSP = newsp
	logger.Infof("successfully configured SAML")
	return nil
}

func BestDomain() string {
	domain := config.FindInfo().Domain
	if domain != "" {
		return domain
	}
	return httpHost
}
