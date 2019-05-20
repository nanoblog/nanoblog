package main

import (
	"net/url"
	"time"
)

var dmanInterval = 30 * time.Second

func dman() {
	logger.Infof("dman> init")

	for {
		time.Sleep(dmanInterval)
		logger.Debugf("dman> running checks")

		now := time.Now().In(getTimezone())
		drafts := config.ListDrafts()
		info := config.FindInfo()

		// Skip because there are no drafts.
		if len(drafts) == 0 {
			logger.Debugf("dman> skipping because there are no drafts")
			continue
		}

		// Skip if not the correct hour.
		if now.Hour() != info.ScheduleHour {
			logger.Debugf("dman> skipping because now %d is not the scheduled hour %d", now.Hour(), info.ScheduleHour)
			continue
		}

		// Skip if most recently posted.
		lastPost, err := config.MostRecentScheduledPost()
		if err == nil {
			lastPostAge := now.Sub(lastPost.Created)
			if info.Schedule > lastPostAge {
				logger.Debugf("dman> skipping draft because schedule %s > post %s", info.Schedule, lastPostAge)
				continue
			}
		}

		draft := drafts[0]
		post, err := config.AddPost(draft.Body, "", true)
		if err != nil {
			logger.Errorf("dman> add post failed: %s", err)
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
