package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v45/github"
	"golang.org/x/oauth2"
)

type UserSession struct {
	AccessToken string
	Username    string
	Email       string
}

type ContributionDay struct {
	Date              string `json:"date"`
	ContributionCount int    `json:"contributionCount"`
}

type CommitPattern struct {
	Pattern  [][]bool `json:"pattern"`
	RepoName string   `json:"repoName"`
}

func init() {
	gob.Register(&UserSession{})
}

func main() {
	r := gin.Default()

	store := cookie.NewStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("commitcanvas", store))

	r.LoadHTMLGlob("templates/*")

	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"repo", "user", "workflow"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		RedirectURL: os.Getenv("GITHUB_REDIRECT_URL"),
	}

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.GET("/api/auth/status", func(c *gin.Context) {
		session := sessions.Default(c)
		userSession := session.Get("user")

		if userSession == nil {
			c.JSON(http.StatusOK, gin.H{
				"authenticated": false,
			})
			return
		}

		user := userSession.(*UserSession)
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"username":      user.Username,
		})
	})

	r.GET("/login", func(c *gin.Context) {
		url := oauth2Config.AuthCodeURL("state")
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/callback", func(c *gin.Context) {
		code := c.Query("code")
		token, err := oauth2Config.Exchange(c, code)
		if err != nil {
			log.Printf("Token exchange error: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		client := github.NewClient(oauth2Config.Client(c, token))

		user, _, err := client.Users.Get(c, "")
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		userSession := &UserSession{
			AccessToken: token.AccessToken,
			Username:    *user.Login,
		}

		if user.Email != nil {
			userSession.Email = *user.Email
		} else {
			emails, _, err := client.Users.ListEmails(c, nil)
			if err == nil && len(emails) > 0 {
				for _, email := range emails {
					if email.Primary != nil && *email.Primary {
						userSession.Email = *email.Email
						break
					}
				}
			}

			if userSession.Email == "" {
				userSession.Email = fmt.Sprintf("%s@users.noreply.github.com", *user.Login)
			}
		}

		session := sessions.Default(c)
		session.Set("user", userSession)
		err = session.Save()
		if err != nil {
			log.Printf("Failed to save session: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		c.HTML(http.StatusOK, "callback.html", gin.H{"error": false})
	})

	r.POST("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	})

	api := r.Group("/api")
	api.Use(authMiddleware())
	{
		api.GET("/contributions", getContributions)
		api.POST("/commits", createCommits)
	}

	r.Run(":8080")
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userSession := session.Get("user")
		if userSession == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func getContributions(c *gin.Context) {
	session := sessions.Default(c)
	userSession := session.Get("user").(*UserSession)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: userSession.AccessToken})
	tc := oauth2.NewClient(c, ts)
	client := github.NewClient(tc)

	query := `
    query($from: DateTime!, $to: DateTime!) {
        viewer {
            contributionsCollection(from: $from, to: $to) {
                contributionCalendar {
                    totalContributions
                    weeks {
                        contributionDays {
                            contributionCount
                            date
                            weekday
                        }
                    }
                }
            }
        }
    }`

	to := time.Now().UTC().Add(time.Hour * 9)
	from := to.AddDate(-1, 0, 0)
	for from.Weekday() != time.Sunday {
		from = from.AddDate(0, 0, 1)
	}

	variables := map[string]interface{}{
		"from": from.Format(time.RFC3339),
		"to":   to.Add(time.Hour * 24).Format(time.RFC3339),
	}

	req, err := client.NewRequest("POST", "graphql", map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create request: %v", err)})
		return
	}

	var response map[string]interface{}
	_, err = client.Do(c.Request.Context(), req, &response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to fetch contributions: %v", err)})
		return
	}

	data := response["data"].(map[string]interface{})
	viewer := data["viewer"].(map[string]interface{})
	collection := viewer["contributionsCollection"].(map[string]interface{})
	calendar := collection["contributionCalendar"].(map[string]interface{})
	weeks := calendar["weeks"].([]interface{})

	var contributions []ContributionDay
	for _, week := range weeks {
		weekData := week.(map[string]interface{})
		days := weekData["contributionDays"].([]interface{})
		for _, day := range days {
			dayData := day.(map[string]interface{})
			contributions = append(contributions, ContributionDay{
				Date:              dayData["date"].(string),
				ContributionCount: int(dayData["contributionCount"].(float64)),
			})
		}
	}

	c.JSON(http.StatusOK, contributions)
}

func createCommits(c *gin.Context) {
	session := sessions.Default(c)
	userSession := session.Get("user").(*UserSession)

	var req CommitPattern
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: userSession.AccessToken})
	tc := oauth2.NewClient(c, ts)
	client := github.NewClient(tc)

	repoPath := filepath.Join(os.TempDir(), "commit-canvas", userSession.Username, req.RepoName)
	os.RemoveAll(repoPath)
	defer os.RemoveAll(filepath.Dir(repoPath))

	remoteURL := fmt.Sprintf("https://%s:%s@github.com/%s/%s.git",
		userSession.Username, userSession.AccessToken, userSession.Username, req.RepoName)
	auth := &githttp.BasicAuth{
		Username: userSession.Username,
		Password: userSession.AccessToken,
	}

	var repo *git.Repository
	var w *git.Worktree
	var err error

	if repo, err = git.PlainClone(repoPath, false, &git.CloneOptions{
		URL:          remoteURL,
		Auth:         auth,
		SingleBranch: false,
	}); err != nil {
		if _, _, err = client.Repositories.Get(c, userSession.Username, req.RepoName); err != nil {
			if _, _, err = client.Repositories.Create(c, "", &github.Repository{
				Name:        github.String(req.RepoName),
				Private:     github.Bool(false),
				AutoInit:    github.Bool(false),
				Description: github.String("Created by Commit Canvas"),
			}); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create repository: %v", err)})
				return
			}
		}

		if repo, err = git.PlainInit(repoPath, false); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to init repo: %v", err)})
			return
		}

		if _, err = repo.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: []string{remoteURL},
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create remote: %v", err)})
			return
		}

		if w, err = repo.Worktree(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get worktree: %v", err)})
			return
		}

		if err := os.WriteFile(
			filepath.Join(repoPath, "README.md"),
			[]byte("# Commit Canvas\nCreated by Commit Canvas"),
			0644,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create README: %v", err)})
			return
		}

		if _, err := w.Add("README.md"); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to add README: %v", err)})
			return
		}

		if _, err := w.Commit("Initial commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  userSession.Username,
				Email: userSession.Email,
				When:  time.Now().UTC().Add(time.Hour * 9),
			},
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to commit: %v", err)})
			return
		}

		headRef, err := repo.Head()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get HEAD: %v", err)})
			return
		}

		ref := plumbing.NewHashReference(plumbing.NewBranchReferenceName("commit-canvas"), headRef.Hash())
		if err = repo.Storer.SetReference(ref); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to set commit-canvas branch: %v", err)})
			return
		}

		if err := repo.Push(&git.PushOptions{
			RemoteName: "origin",
			Auth:       auth,
			RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/commit-canvas:refs/heads/commit-canvas")},
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to push: %v", err)})
			return
		}
	}

	if w, err = repo.Worktree(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get worktree: %v", err)})
		return
	}

	branches, _ := repo.Branches()
	branchExists := false
	branches.ForEach(func(branch *plumbing.Reference) error {
		if branch.Name().String() == "refs/heads/commit-canvas" {
			branchExists = true
		}
		return nil
	})

	checkoutOpts := &git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName("commit-canvas"),
		Create: !branchExists,
		Force:  true,
	}

	if err := w.Checkout(checkoutOpts); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to checkout: %v", err)})
		return
	}

	if err := os.MkdirAll(filepath.Join(repoPath, "commits"), 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create directory: %v", err)})
		return
	}

	startDate := time.Now().UTC().Add(time.Hour*9).AddDate(-1, 0, 0)
	for startDate.Weekday() != time.Sunday {
		startDate = startDate.AddDate(0, 0, 1)
	}

	for col := 0; col < len(req.Pattern); col++ {
		for row := 0; row < len(req.Pattern[col]); row++ {
			if !req.Pattern[col][row] {
				continue
			}

			commitDate := startDate.AddDate(0, 0, col*7+row)
			fileName := fmt.Sprintf("commits/%s.txt", commitDate.Format("20060102150405"))

			if err := os.WriteFile(
				filepath.Join(repoPath, fileName),
				[]byte(fmt.Sprintf("Commit content generated at %s\n", commitDate.Format(time.RFC3339))),
				0644,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to write file: %v", err)})
				return
			}

			if _, err := w.Add(fileName); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to add file: %v", err)})
				return
			}

			if _, err := w.Commit(fmt.Sprintf("Commit for %s", commitDate.Format("2006-01-02")), &git.CommitOptions{
				Author: &object.Signature{
					Name:  userSession.Username,
					Email: userSession.Email,
					When:  commitDate,
				},
				Committer: &object.Signature{
					Name:  userSession.Username,
					Email: userSession.Email,
					When:  commitDate,
				},
			}); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to commit: %v", err)})
				return
			}
		}
	}

	if err := repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      true,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to push: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commits created successfully"})
}
