package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ChimeraCoder/anaconda"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	humanize "github.com/dustin/go-humanize"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/publicsuffix"
	xurls "mvdan.cc/xurls"
)

var (
	SessionCookieName    = "__nanoblog_session"
	SessionCookieNameSSO = "__nanoblog_sso_session"

	urlRegexp       = xurls.Relaxed()
	linebreakRegexp = regexp.MustCompile(`\r?\n`)
	hashtagRegexp   = regexp.MustCompile(`#(\S+)`)
	imageRegexp     = regexp.MustCompile(`\.(?i:jpeg|jpg|png|gif)`)
)

type Session struct {
	Admin     bool
	NotBefore time.Time
	NotAfter  time.Time
}

type Web struct {
	// Internal
	w        http.ResponseWriter
	r        *http.Request
	ps       httprouter.Params
	template string

	// Default
	HTTPHost string
	Admin    bool
	Backlink string
	Version  string
	Request  *http.Request
	Section  string
	Time     time.Time
	Info     Info
	SAML     *samlsp.Middleware
	Email    string

	// Paging
	Page int

	// Additional
	Twitter *anaconda.TwitterApi

	Post       Post
	Posts      []Post
	PostParent Post

	Draft  Draft
	Drafts []Draft
}

func init() {
	gob.Register(Session{})
}

func Error(w http.ResponseWriter, err error) {
	logger.Error(err)

	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, errorPageHTML+"\n")
}

func (w *Web) HTML() {
	t := template.New(w.template).Funcs(template.FuncMap{
		"hasprefix": strings.HasPrefix,
		"hassuffix": strings.HasSuffix,
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"bytes": func(n int64) string {
			return fmt.Sprintf("%.2f GB", float64(n)/1024/1024/1024)
		},
		"hourstamp": func(hour int) string {
			t := time.Date(0, 0, 0, hour, 0, 0, 0, time.UTC)
			return t.Format(time.Kitchen)
		},
		"days": func(d time.Duration) string {
			return fmt.Sprintf("%0.f", d.Hours()/float64(24))
		},
		"date": func(t time.Time) string {
			return t.Format(time.UnixDate)
		},
		"dateshort": func(t time.Time) string {
			now := time.Now().In(t.Location())
			diff := now.Sub(t)

			if diff < (59 * time.Second) {
				return fmt.Sprintf("%.0fs", diff.Seconds())
			} else if diff < (59 * time.Minute) {
				return fmt.Sprintf("%.0fm", diff.Minutes())
			} else if diff < (24 * time.Hour) {
				return fmt.Sprintf("%.0fh", diff.Hours())
			} else if t.Year() == now.Year() {
				return t.Format("3:04 PM · Jan 2")
			}
			return t.Format("3:04 PM · Jan 2 2006")
		},
		"time": humanize.Time,
		"jsfloat64": func(n float64) template.JS {
			return template.JS(fmt.Sprintf("%.0f", n))
		},
		"jsint": func(n int) template.JS {
			return template.JS(fmt.Sprintf("%d", n))
		},
		"jsint64": func(n int) template.JS {
			return template.JS(fmt.Sprintf("%d", n))
		},
		"safehtml": func(s string) template.HTML {
			return template.HTML(s)
		},
		"enhance": func(s string) template.HTML {
			// Linkify URLs and display inline media.
			matches := urlRegexp.FindAllString(s, -1)
			for _, match := range matches {
				tmpurl := match

				if !strings.HasPrefix(match, "http") {
					tmpurl = "https://" + match
				}
				u, err := url.Parse(tmpurl)
				if err != nil {
					continue
				}
				if u.Scheme != "http" && u.Scheme != "https" {
					continue
				}
				if u.Host == "" {
					continue
				}
				if u.Path == "" {
					u.Path = "/"
				}

				var link string

				if imageRegexp.MatchString(u.Path) {
					// Display image inline.
					link = fmt.Sprintf(`<a href="%s" target="_blank"><img src="%s" class="ui fluid rounded bordered image"></a>`, u.String(), u.String())
				} else {
					// Linkify URL
					host := strings.TrimPrefix(u.Host, "www.")
					link = fmt.Sprintf(`<a href="%s" title="%s">%s%s</a>`, u.String(), u.String(), host, u.Path)
				}
				s = strings.ReplaceAll(s, match, link)
			}

			// Create linebreaks.
			s = linebreakRegexp.ReplaceAllString(s, "<br>\n")

			// Linkify hashtags.
			s = hashtagRegexp.ReplaceAllString(s, `<a href="/?q=%23${1}">#${1}</a>`)

			return template.HTML(s)
		},
		"truncate": func(s string, n int) string {
			if len(s) > n {
				s = s[:n-3] + "..."
			}
			return s
		},
		"timestamp": func(n int64) string {
			t := time.Unix(n, 0).Local()
			return t.Format("2006/01/02")
		},
		"linebreaks": func(s string) template.HTML {
			return template.HTML(strings.Replace(s, "\n", "\n<br>\n", -1))
		},
		"ssoprovider": func() string {
			if samlSP == nil {
				return ""
			}
			redirect, err := url.Parse(samlSP.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding))
			if err != nil {
				logger.Warnf("SSO redirect invalid URL: %s", err)
				return "unknown"
			}
			domain, err := publicsuffix.EffectiveTLDPlusOne(redirect.Host)
			if err != nil {
				logger.Warnf("SSO redirect invalid URL domain: %s", err)
				return "unknown"
			}
			suffix, icann := publicsuffix.PublicSuffix(domain)
			if icann {
				suffix = "." + suffix
			}
			return strings.Title(strings.TrimSuffix(domain, suffix))
		},
	})

	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "templates/") {
			continue
		}
		name := strings.TrimPrefix(filename, "templates/")
		b, err := Asset(filename)
		if err != nil {
			Error(w.w, err)
			return
		}

		var tmpl *template.Template
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(string(b)); err != nil {
			Error(w.w, err)
			return
		}
	}

	w.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w.w, w); err != nil {
		Error(w.w, err)
		return
	}
}

func (w *Web) NotFound() {
	http.NotFound(w.w, w.r)
}

func (w *Web) Redirect(format string, a ...interface{}) {
	location := fmt.Sprintf(format, a...)
	http.Redirect(w.w, w.r, location, http.StatusFound)
}

func WebHandler(h func(*Web), section string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		web := &Web{
			w:        w,
			r:        r,
			ps:       ps,
			template: section + ".html",

			HTTPHost: httpHost,
			Backlink: backlink,
			Time:     time.Now().In(getTimezone()),
			Version:  version,
			Request:  r,
			Section:  section,
			Info:     config.FindInfo(),

			Twitter: twitterAPI,
			SAML:    samlSP,
		}

		var public = map[string]bool{
			"signin":     true,
			"forgot":     true,
			"index":      true,
			"configure":  true,
			"profile":    true,
			"banner":     true,
			"posts/view": true,
			"domain":     true,
		}

		if section == "signout" {
			h(web)
			return
		}

		// Send user to custom domain URL if one is configured.
		// Without forcing them, so they can avoid it if there's a DNS issue, etc.
		if domain := config.FindInfo().Domain; domain != "" {
			if r.Host != domain {
				if section == "index" {
					web.Redirect("/domain")
					return
				}
			}
		}

		// Has a valid session.
		if session, _ := ValidateSession(r); session != nil {
			logger.Infof("session exists admin is %t", session.Admin)
			web.Admin = session.Admin
		} else if samlSP != nil {
			// SAML auth.
			if token := samlSP.GetAuthorizationToken(r); token != nil {
				r = r.WithContext(samlsp.WithToken(r.Context(), token))

				email := token.StandardClaims.Subject
				if email == "" {
					Error(w, fmt.Errorf("SAML token missing email"))
					return
				}

				web.Email = email
				web.Admin = true

				logger.Debugf("valid SSO token, signing in session")
				if err := web.SigninSession(true); err != nil {
					Error(web.w, err)
					return
				}
			}
		}

		if web.Admin || public[section] {
			h(web)
			return
		}

		if !config.FindInfo().Configured {
			web.Redirect("/configure")
			return
		}

		logger.Warnf("auth: sign in required")
		web.Redirect("/signin")
	}
}

func Log(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		h(w, r, ps)
		rang := r.Header.Get("Range")
		logger.Infof("%d %q %s %q %d ms", start.Unix(), rang, r.Method, r.RequestURI, int64(time.Since(start)/time.Millisecond))
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serveAsset(w, r, ps.ByName("path"))
}

func serveAsset(w http.ResponseWriter, r *http.Request, filename string) {
	path := "static" + filename

	b, err := Asset(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fi, err := AssetInfo(path)
	if err != nil {
		Error(w, err)
		return
	}
	http.ServeContent(w, r, path, fi.ModTime(), bytes.NewReader(b))
}

func ValidateSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("auth: missing cookie")
	}
	session := &Session{}
	if err := securetoken.Decode(SessionCookieName, cookie.Value, session); err != nil {
		return nil, err
	}
	if time.Now().Before(session.NotBefore) {
		return nil, fmt.Errorf("invalid session (before valid)")
	}
	if time.Now().After(session.NotAfter) {
		return nil, fmt.Errorf("invalid session (expired session.NotAfter is %s and now is %s)", session.NotAfter, time.Now())
	}
	return session, nil
}

func (w *Web) SignoutSession() {
	domain, _, err := net.SplitHostPort(w.r.Host)
	if err != nil {
		logger.Warnf("parsing Host header failed: %s", err)
	}
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieNameSSO,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !httpInsecure,
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !httpInsecure,
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func (w *Web) SigninSession(admin bool) error {
	expires := time.Now().Add(12 * time.Hour)

	encoded, err := securetoken.Encode(SessionCookieName, Session{
		Admin:     admin,
		NotBefore: time.Now(),
		NotAfter:  expires,
	})
	if err != nil {
		return fmt.Errorf("auth: encoding error: %s", err)
	}
	domain, _, err := net.SplitHostPort(w.r.Host)
	if err != nil {
		logger.Warnf("parsing Host header failed: %s", err)
	}
	logger.Infof("HTTP INSECURE IS %t (so Secure: %t)", httpInsecure, !httpInsecure)
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   !httpInsecure,
		Expires:  expires,
	})
	return nil
}
