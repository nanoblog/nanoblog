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

	"golang.org/x/crypto/bcrypt"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

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

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimRight(domain, "/")

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

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
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

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	http.SetCookie(w.w, NewDeletionCookie())
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
	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/")
}

func indexHandler(w *Web) {
	if !config.FindInfo().Configured {
		w.Redirect("/configure")
		return
	}

	var posts []Post

	if query := w.r.FormValue("q"); query != "" {
		posts = config.SearchPosts(query)
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

func adminScheduleHandler(w *Web) {
	scheduleHours, _ := strconv.Atoi(w.r.FormValue("schedule"))
	schedule := time.Duration(scheduleHours) * time.Hour

	config.UpdateInfo(func(i *Info) error {
		i.Schedule = schedule
		return nil
	})

	w.Redirect("/admin")
}

func adminSettingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")
	name := strings.TrimSpace(w.r.FormValue("name"))
	description := strings.TrimSpace(w.r.FormValue("description"))
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	headerlink1 := strings.TrimSpace(w.r.FormValue("headerlink1"))
	headerlink1URL := strings.TrimSpace(w.r.FormValue("headerlink1_url"))
	headerlink2 := strings.TrimSpace(w.r.FormValue("headerlink2"))
	headerlink2URL := strings.TrimSpace(w.r.FormValue("headerlink2_url"))
	headerlink3 := strings.TrimSpace(w.r.FormValue("headerlink3"))
	headerlink3URL := strings.TrimSpace(w.r.FormValue("headerlink3_url"))

	snippet := strings.TrimSpace(w.r.FormValue("snippet"))

	twitterConsumerKey := strings.TrimSpace(w.r.FormValue("twitter_consumer_key"))
	twitterConsumerSecret := strings.TrimSpace(w.r.FormValue("twitter_consumer_secret"))
	twitterAccessToken := strings.TrimSpace(w.r.FormValue("twitter_access_token"))
	twitterAccessTokenSecret := strings.TrimSpace(w.r.FormValue("twitter_access_token_secret"))

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

	// Banner
	//if file, fileHeader, err := w.r.FormFile("banner"); fileHeader != nil && err == nil {
	//	defer file.Close()

	//	banner, err := os.Create(bannerFilename)
	//	if err != nil {
	//		w.Redirect("/admin?error=banner")
	//		return
	//	}
	//	if _, err := io.Copy(banner, file); err != nil {
	//		w.Redirect("/admin?error=banner")
	//		return
	//	}
	//	if err := banner.Close(); err != nil {
	//		w.Redirect("/admin?error=banner")
	//		return
	//	}
	//}

	if name == "" {
		name = "Unnamed Blog"
	}

	if headerlink1 == "" {
		headerlink1 = name
		headerlink1URL = "/"
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimRight(domain, "/")

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
			i.Email = email
			i.Password = hashedPassword
			return nil
		})
	}

	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Name = name
		i.Description = description
		i.Domain = domain
		i.Headerlink1 = headerlink1
		i.Headerlink1URL = headerlink1URL
		i.Headerlink2 = headerlink2
		i.Headerlink2URL = headerlink2URL
		i.Headerlink3 = headerlink3
		i.Headerlink3URL = headerlink3URL
		i.Snippet = snippet

		i.Twitter.ConsumerKey = twitterConsumerKey
		i.Twitter.ConsumerSecret = twitterConsumerSecret
		i.Twitter.AccessToken = twitterAccessToken
		i.Twitter.AccessTokenSecret = twitterAccessTokenSecret
		return nil
	})

	if err := updateTwitterAPI(); err != nil {
		w.Redirect("/admin/settings?error=twitter")
		return
	}

	w.Redirect("/admin/settings?success=changes")
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

	var (
		inReplyToStatusId int64 = 0
		parentID                = ""
	)

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
			post, err := config.AddPost(body, parentID)
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
