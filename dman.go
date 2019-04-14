package main

import (
	"net/url"
	"time"
)

var dmanDelay = 10 * time.Minute

func dman() {
	logger.Infof("dman> init")

	for {
		time.Sleep(dmanDelay)

		drafts := config.ListDrafts()
		info := config.FindInfo()

		logger.Infof("dman> there are %d drafts", len(drafts))

		// No drafts
		if len(drafts) == 0 {
			continue
		}
		draft := drafts[0]

		posts := config.ListPosts()
		if len(posts) > 0 {
			mostrecent := time.Now().Sub(posts[0].Created)
			if info.Schedule > mostrecent {
				logger.Infof("dman> skipping draft because schedule %s > post %s", info.Schedule, mostrecent)
				continue
			}
			logger.Infof("dman> adding draft because most recent post is %s old", mostrecent)
		}

		post, err := config.AddPost(draft.Body, "")
		if err != nil {
			logger.Warnf("dman> add post failed: %s", err)
			continue
		}
		config.DeleteDraft(draft.ID)
		logger.Infof("dman> added post %s from draft %s", post.ID, draft.ID)

		if twitterAPI != nil {
			tweet, err := twitterAPI.PostTweet(post.Body, url.Values{})
			if err == nil {
				config.UpdatePost(post.ID, func(p *Post) error {
					p.Tweet = tweet.Id
					return nil
				})
			}
		}
	}
}
