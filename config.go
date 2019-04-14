package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrPostNotFound    = errors.New("post not found")
	ErrPostDuplicateID = errors.New("duplicate post ID")

	ErrDraftNotFound    = errors.New("draft not found")
	ErrDraftDuplicateID = errors.New("duplicate draft ID")
)

type Info struct {
	Email          string        `json:"email"`
	Password       []byte        `json:"password"`
	Secret         string        `json:"secret"`
	Configured     bool          `json:"configure"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Domain         string        `json:"domain"`
	Headerlink1    string        `json:"headerlink1"`
	Headerlink1URL string        `json:"headerlink1_url"`
	Headerlink2    string        `json:"headerlink2"`
	Headerlink2URL string        `json:"headerlink2_url"`
	Headerlink3    string        `json:"headerlink3"`
	Headerlink3URL string        `json:"headerlink3_url"`
	Snippet        string        `json:"snippet"`
	Schedule       time.Duration `json:"schedule"`
	HashKey        string        `json:"hash_key"`
	BlockKey       string        `json:"block_key"`
	Mail           struct {
		From     string `json:"from"`
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"mail"`
	Twitter struct {
		ConsumerKey       string `json:"consumer_key"`
		ConsumerSecret    string `json:"consumer_secret"`
		AccessToken       string `json:"acess_token"`
		AccessTokenSecret string `json:"access_token_secret"`

		ID         int64  `json:"id"`
		ScreenName string `json:"screen_name"`
	} `json:"twitter"`
}

type Config struct {
	mu       sync.RWMutex
	filename string

	Info   *Info    `json:"info"`
	Posts  []*Post  `json:"posts"`
	Drafts []*Draft `json:"drafts"`

	Modified time.Time `json:"modified"`
}

func NewConfig(filename string) (*Config, error) {
	filename = filepath.Join(datadir, filename)
	c := &Config{filename: filename}
	b, err := ioutil.ReadFile(filename)

	// Create new config with defaults
	if os.IsNotExist(err) {
		c.Info = &Info{
			HashKey:  randomString(32),
			BlockKey: randomString(32),
			Schedule: 24 * time.Hour,
		}
		return c, c.save()
	}
	if err != nil {
		return nil, err
	}

	// Open existing config
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("invalid config %q: %s", filename, err)
	}

	return c, nil
}

func (c *Config) Lock(loc string) {
	c.mu.Lock()
}

func (c *Config) Unlock(loc string) {
	c.mu.Unlock()
}

func (c *Config) RLock(loc string) {
	c.mu.RLock()
}

func (c *Config) RUnlock(loc string) {
	c.mu.RUnlock()
}

func (c *Config) FindInfo() Info {
	c.RLock("FindInfo")
	defer c.RUnlock("FindInfo")
	return *c.Info
}

func (c *Config) UpdateInfo(fn func(*Info) error) error {
	c.Lock("UpdateInfo")
	defer c.Unlock("UpdateInfo")
	if err := fn(c.Info); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) save() error {
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return overwrite(c.filename, b, 0644)
}

//
// Draft
//

type Draft struct {
	ID      string    `json:"id"`
	Body    string    `json:"body"`
	Created time.Time `json:"created"`
}

func (c *Config) ListDrafts() []Draft {
	c.RLock("ListDrafts")
	defer c.RUnlock("ListDrafts")
	var drafts []Draft
	for _, d := range c.Drafts {
		drafts = append(drafts, *d)
	}
	return drafts
}

func (c *Config) AddDraft(body string) (Draft, error) {
	c.Lock("AddDraft")
	defer c.Unlock("AddDraft")

	draftID := randomString(15)
	if _, err := c.findDraft(draftID); err != ErrDraftNotFound {
		return Draft{}, ErrDraftDuplicateID
	}

	draft := Draft{
		ID:      draftID,
		Body:    body,
		Created: time.Now(),
	}

	c.Drafts = append(c.Drafts, &draft)
	return draft, c.save()
}

func (c *Config) DeleteDraft(id string) error {
	c.Lock("DeleteDraft")
	defer c.Unlock("DeleteDraft")
	var drafts []*Draft
	for _, d := range c.Drafts {
		if d.ID == id {
			continue
		}
		drafts = append(drafts, d)
	}
	c.Drafts = drafts
	return c.save()
}

func (c *Config) FindDraft(id string) (Draft, error) {
	c.RLock("FindDraft")
	defer c.RUnlock("FindDraft")
	d, err := c.findDraft(id)
	if err != nil {
		return Draft{}, err
	}
	return *d, c.save()
}

func (c *Config) findDraft(id string) (*Draft, error) {
	for _, d := range c.Drafts {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, ErrDraftNotFound
}

//
// Post
//

type Post struct {
	ID       string    `json:"id"`
	Body     string    `json:"body"`
	Tweet    int64     `json:"tweet"`
	ParentID string    `json:"parent"`
	Created  time.Time `json:"created"`

	Thread []Post `json:"-"`
}

func (c *Config) SearchPosts(query string) []Post {
	c.RLock("SearchPosts")
	defer c.RUnlock("SearchPosts")
	if len(c.Posts) == 0 {
		return nil
	}

	keywords := []string{}
	for _, kw := range strings.Fields(query) {
		keywords = append(keywords, strings.ToLower(kw))
	}

	var posts []Post
	for i := len(c.Posts) - 1; i >= 0; i-- {
		p := c.Posts[i]
		match := false
		for _, kw := range keywords {
			if strings.Contains(strings.ToLower(p.Body), kw) {
				match = true
				break
			}
		}
		if match {
			posts = append(posts, *p)
		}
	}
	return posts
}

func (c *Config) ListParentPosts() []Post {
	c.RLock("ListParentPosts")
	defer c.RUnlock("ListParentPosts")
	if len(c.Posts) == 0 {
		return nil
	}

	var posts []Post
	for i := len(c.Posts) - 1; i >= 0; i-- {
		post := *c.Posts[i]
		if post.ParentID != "" {
			continue
		}

		parentID := post.ID
		for _, p := range c.Posts {
			if p.ParentID != parentID {
				continue
			}
			post.Thread = append(post.Thread, *p)
			parentID = p.ID
		}
		posts = append(posts, post)
	}
	return posts
}

func (c *Config) ListPosts() []Post {
	c.RLock("ListPosts")
	defer c.RUnlock("ListPosts")
	if len(c.Posts) == 0 {
		return nil
	}

	var posts []Post
	for i := len(c.Posts) - 1; i >= 0; i-- {
		p := c.Posts[i]
		posts = append(posts, *p)
	}
	return posts
}

func (c *Config) AddPost(body, parentID string) (Post, error) {
	c.Lock("AddPost")
	defer c.Unlock("AddPost")

	postID := randomString(15)
	if _, err := c.findPost(postID); err != ErrPostNotFound {
		return Post{}, ErrPostDuplicateID
	}

	/*
		if len(c.Posts) > 0 {
			p := c.Posts[len(c.Posts)-1]
			if created.Sub(p.Created) < (1 * time.Minute) {
				parentID = p.ID
				p.ChildID = postID
			}
		}
	*/

	post := Post{
		ID:       postID,
		Body:     body,
		ParentID: parentID,
		Created:  time.Now(),
	}

	c.Posts = append(c.Posts, &post)
	return post, c.save()
}

func (c *Config) DeletePost(id string) error {
	c.Lock("DeletePost")
	defer c.Unlock("DeletePost")
	var posts []*Post
	for _, p := range c.Posts {
		if p.ID == id {
			continue
		}
		posts = append(posts, p)
	}
	c.Posts = posts
	return c.save()
}

func (c *Config) FindPost(id string) (Post, error) {
	c.RLock("FindPost")
	defer c.RUnlock("FindPost")
	p, err := c.findPost(id)
	if err != nil {
		return Post{}, err
	}
	post := *p

	parentID := post.ID
	for _, p := range c.Posts {
		if p.ParentID != parentID {
			continue
		}
		post.Thread = append(post.Thread, *p)
		parentID = p.ID
	}
	return post, c.save()
}

func (c *Config) findPost(id string) (*Post, error) {
	for _, p := range c.Posts {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrPostNotFound
}

func (c *Config) UpdatePost(id string, fn func(*Post) error) error {
	c.Lock("UpdatePost")
	defer c.Unlock("UpdatePost")
	t, err := c.findPost(id)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		return err
	}
	return c.save()
}
