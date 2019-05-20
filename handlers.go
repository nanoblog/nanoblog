package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{8,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

func ssoHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if token := samlSP.GetAuthorizationToken(r); token != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	logger.Debugf("SSO: require account handler")
	samlSP.RequireAccountHandler(w, r)
	return
}

func samlHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if samlSP == nil {
		Error(w, fmt.Errorf("SAML is not configured"))
		return
	}
	logger.Debugf("SSO: samlSP.ServeHTTP")
	samlSP.ServeHTTP(w, r)
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")
	name := strings.TrimSpace(w.r.FormValue("name"))
	description := strings.TrimSpace(w.r.FormValue("description"))
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	if name == "" {
		name = "Unnamed Blog"
	}

	// Domain
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimRight(domain, "/")
	domain = strings.TrimRight(domain, ".")
	domain = strings.TrimLeft(domain, ".")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Name = name
		i.Description = description
		i.Domain = domain
		i.Password = hashedPassword
		i.Configured = true
		i.Headerlink1 = name
		i.Headerlink1URL = "/"
		return nil
	})

	if err := w.SigninSession(true); err != nil {
		Error(w.w, err)
		return
	}

	w.Redirect("/")
	return
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = randomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	if err := w.SigninSession(true); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	w.SignoutSession()
	w.Redirect("/")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	if err := w.SigninSession(true); err != nil {
		Error(w.w, err)
		return
	}

	w.Redirect("/admin/settings")
}

func domainHandler(w *Web) {
	w.HTML()
}

func indexHandler(w *Web) {
	if !config.FindInfo().Configured {
		w.Redirect("/configure")
		return
	}

	var posts []Post

	if query := w.r.FormValue("q"); query != "" {
		posts = config.SearchPosts(query)
	} else if w.r.FormValue("all") == "yes" {
		posts = config.ListPosts()
	} else {
		posts = config.ListParentPosts()
	}

	w.Posts = posts
	w.HTML()
}

func postsViewHandler(w *Web) {
	post, err := config.FindPost(w.ps.ByName("post"))
	if err != nil {
		w.NotFound()
		return
	}

	var posts []Post
	posts = append(posts, post)
	posts = append(posts, post.Thread...)

	// Last post becomes parent to replies.
	for _, p := range posts {
		w.PostParent = p
	}

	w.Post = post
	w.Posts = posts
	w.HTML()
}

func profileHandler(w *Web) {
	if _, err := os.Stat(profileFilename); err != nil {
		w.Redirect("/static/favicon.png")
		return
	}
	http.ServeFile(w.w, w.r, profileFilename)
}

/*
func bannerHandler(w *Web) {
	if _, err := os.Stat(bannerFilename); err != nil {
		w.Redirect("/static/banner.jpg")
		return
	}
	http.ServeFile(w.w, w.r, bannerFilename)
}
*/
func adminScheduleHourHandler(w *Web) {
	w.Redirect("/admin")
}

func adminScheduleHandler(w *Web) {
	scheduleInterval, _ := strconv.Atoi(w.r.FormValue("schedule"))
	schedule := time.Duration(scheduleInterval) * time.Hour

	scheduleHour, _ := strconv.Atoi(w.r.FormValue("hour"))
	if scheduleHour < 0 {
		scheduleHour = 0
	}
	if scheduleHour > 23 {
		scheduleHour = 23
	}

	config.UpdateInfo(func(i *Info) error {
		i.Schedule = schedule
		i.ScheduleHour = scheduleHour
		return nil
	})

	w.Redirect("/admin")
}

func adminSettingsIndexHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	name := strings.TrimSpace(w.r.FormValue("name"))
	description := strings.TrimSpace(w.r.FormValue("description"))
	location := strings.TrimSpace(w.r.FormValue("location"))
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	// Email
	if !validEmail.MatchString(email) {
		w.Redirect("/admin/settings?error=invalid")
		return
	}

	// Timezone
	if location != "" {
		if err := setTimezone(location); err != nil {
			Error(w.w, err)
			return
		}
	}

	// Name
	if name == "" {
		name = "Unnamed Blog"
	}

	// Domain
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimRight(domain, "/")
	domain = strings.TrimRight(domain, ".")
	domain = strings.TrimLeft(domain, ".")

	// Profile
	if file, fileHeader, err := w.r.FormFile("profile"); fileHeader != nil && err == nil {
		defer file.Close()

		profile, err := os.Create(profileFilename)
		if err != nil {
			w.Redirect("/admin/settings?error=profile")
			return
		}
		if _, err := io.Copy(profile, file); err != nil {
			w.Redirect("/admin/settings?error=profile")
			return
		}
		if err := profile.Close(); err != nil {
			w.Redirect("/admin/settings?error=profile")
			return
		}
	}

	// If domain changes we need to re-configure SAML.
	// This updates the cookie domain.
	if config.FindInfo().Domain != domain {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
			w.Redirect("/admin/settings/sso?error=saml")
			return
		}
		return
	}

	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Name = name
		i.Description = description
		i.Location = location
		i.Domain = domain
		return nil
	})

	w.Redirect("/admin/settings?success=changes")
}

func adminSettingsMenuHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	headerlink1 := strings.TrimSpace(w.r.FormValue("headerlink1"))
	headerlink1URL := strings.TrimSpace(w.r.FormValue("headerlink1_url"))
	headerlink2 := strings.TrimSpace(w.r.FormValue("headerlink2"))
	headerlink2URL := strings.TrimSpace(w.r.FormValue("headerlink2_url"))
	headerlink3 := strings.TrimSpace(w.r.FormValue("headerlink3"))
	headerlink3URL := strings.TrimSpace(w.r.FormValue("headerlink3_url"))

	config.UpdateInfo(func(i *Info) error {
		if headerlink1 == "" {
			i.Headerlink1 = i.Name
			i.Headerlink1URL = "/"
		} else {
			i.Headerlink1 = headerlink1
			i.Headerlink1URL = headerlink1URL
		}

		i.Headerlink2 = headerlink2
		i.Headerlink2URL = headerlink2URL
		i.Headerlink3 = headerlink3
		i.Headerlink3URL = headerlink3URL
		return nil
	})

	w.Redirect("/admin/settings/menu?success=changes")
}

func adminSettingsSSOHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	samlMetadata := strings.TrimSpace(w.r.FormValue("saml_metadata"))

	config.UpdateInfo(func(i *Info) error {
		i.SAML.IDPMetadata = samlMetadata
		return nil
	})

	// Configure SAML if metadata is present.
	if len(samlMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
			w.Redirect("/admin/settings/sso?error=saml")
			return
		}
	} else {
		samlSP = nil
	}

	w.Redirect("/admin/settings/sso?success=changes")
}

func adminSettingsAPIHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	twitterConsumerKey := strings.TrimSpace(w.r.FormValue("twitter_consumer_key"))
	twitterConsumerSecret := strings.TrimSpace(w.r.FormValue("twitter_consumer_secret"))
	twitterAccessToken := strings.TrimSpace(w.r.FormValue("twitter_access_token"))
	twitterAccessTokenSecret := strings.TrimSpace(w.r.FormValue("twitter_access_token_secret"))

	config.UpdateInfo(func(i *Info) error {
		i.Twitter.ConsumerKey = twitterConsumerKey
		i.Twitter.ConsumerSecret = twitterConsumerSecret
		i.Twitter.AccessToken = twitterAccessToken
		i.Twitter.AccessTokenSecret = twitterAccessTokenSecret
		return nil
	})

	if err := updateTwitterAPI(); err != nil {
		w.Redirect("/admin/settings/api?error=twitter")
		return
	}

	w.Redirect("/admin/settings/api?success=changes")
}

func adminSettingsSnippetHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	snippet := strings.TrimSpace(w.r.FormValue("snippet"))

	config.UpdateInfo(func(i *Info) error {
		i.Snippet = snippet
		return nil
	})

	w.Redirect("/admin/settings/snippet?success=changes")
}

func adminSettingsPasswordHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/admin/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/admin/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/admin/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Password = hashedPassword
			return nil
		})
	}

	w.Redirect("/admin/settings/password?success=changes")
}

func helpHandler(w *Web) {
	w.HTML()
}

func adminIndexHandler(w *Web) {
	w.Drafts = config.ListDrafts()
	w.HTML()
}

func draftsDeleteHandler(w *Web) {
	draft, err := config.FindDraft(w.ps.ByName("draft"))
	if err != nil {
		w.Redirect("/?error=notfound")
		return
	}
	config.DeleteDraft(draft.ID)
	w.Redirect("/admin")
}

func postsAddHandler(w *Web) {
	w.r.ParseForm()
	queue := w.r.FormValue("queue") == "yes"

	inReplyToStatusId, _ := strconv.ParseInt(w.r.FormValue("in_reply_to_status"), 10, 64)
	parentID := w.r.FormValue("parent")

	for _, body := range w.r.PostForm["body"] {
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		if queue {
			if _, err := config.AddDraft(body); err != nil {
				w.Redirect("/?error=database")
				return
			}
		} else {
			post, err := config.AddPost(body, parentID, false)
			if err != nil {
				w.Redirect("/?error=database")
				return
			}
			parentID = post.ID

			if twitterAPI != nil {
				params := url.Values{}
				if inReplyToStatusId > 0 {
					params.Add("in_reply_to_status_id", fmt.Sprintf("%d", inReplyToStatusId))
				}
				logger.Infof("tweeting post %s %s", post.ID, post.Body)
				tweet, err := twitterAPI.PostTweet(post.Body, params)
				if err == nil {
					config.UpdatePost(post.ID, func(p *Post) error {
						p.Tweet = tweet.Id
						return nil
					})
					inReplyToStatusId = tweet.Id
				} else {
					logger.Warnf("twitter tweet post %s failed: %s", post.ID, err)
				}
			}

		}
	}

	if queue {
		w.Redirect("/admin")
		return
	}

	w.Redirect("/")
}

func postsDeleteHandler(w *Web) {
	from := w.r.FormValue("f")

	post, err := config.FindPost(w.ps.ByName("post"))
	if err != nil {
		w.Redirect("/?error=notfound")
		return
	}
	config.DeletePost(post.ID)

	if twitterAPI != nil && post.Tweet > 0 {
		if _, err := twitterAPI.DeleteTweet(post.Tweet, false); err != nil {
			logger.Warnf("twitter delete tweet post %s tweet %d", post.ID, post.Tweet)
		}
	}
	if from != "" && from != post.ID {
		if _, err := config.FindPost(from); err == nil {
			w.Redirect("/posts/%s", from)
			return
		}
	}
	w.Redirect("/")
}
