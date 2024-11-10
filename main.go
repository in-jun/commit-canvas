package main

import (
	"context"
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

// Types
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

type AppConfig struct {
	oauth2Config *oauth2.Config
	store        sessions.Store
}

// Constants
const (
	sessionName   = "commitcanvas"
	sessionMaxAge = 86400 * 7
	defaultBranch = "commit-canvas"
	readmeContent = "# Commit Canvas\nCreated by Commit Canvas"
)

func init() {
	gob.Register(&UserSession{})
}

func main() {
	r := gin.Default()

	config := &AppConfig{
		oauth2Config: &oauth2.Config{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			Scopes:       []string{"repo", "user", "workflow"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			RedirectURL: "http://localhost:8080/callback",
		},
		store: cookie.NewStore([]byte(os.Getenv("SESSION_SECRET"))),
	}

	config.store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	setupRouter(r, config)
	r.Run(":8080")
}

func setupRouter(r *gin.Engine, config *AppConfig) {
	r.Use(sessions.Sessions(sessionName, config.store))
	r.LoadHTMLGlob("templates/*")

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.GET("/api/auth/status", func(c *gin.Context) {
		session := sessions.Default(c)
		userSession := session.Get("user")

		if userSession == nil {
			c.JSON(http.StatusOK, gin.H{"authenticated": false})
			return
		}

		user := userSession.(*UserSession)
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"username":      user.Username,
		})
	})

	r.GET("/login", func(c *gin.Context) {
		url := config.oauth2Config.AuthCodeURL("state")
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/callback", handleCallback(config))
	r.POST("/logout", handleLogout)

	// Protected routes
	api := r.Group("/api")
	api.Use(authMiddleware())
	{
		api.GET("/contributions", handleGetContributions)
		api.POST("/commits", handleCreateCommits)
	}
}

func handleCallback(config *AppConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		token, err := config.oauth2Config.Exchange(c, code)
		if err != nil {
			log.Printf("Token exchange error: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		client := github.NewClient(config.oauth2Config.Client(c, token))
		user, _, err := client.Users.Get(c, "")
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		userSession := &UserSession{
			AccessToken: token.AccessToken,
			Username:    *user.Login,
			Email:       determineUserEmail(client, user, c),
		}

		session := sessions.Default(c)
		session.Set("user", userSession)
		if err := session.Save(); err != nil {
			log.Printf("Failed to save session: %v", err)
			c.HTML(http.StatusOK, "callback.html", gin.H{"error": true})
			return
		}

		c.HTML(http.StatusOK, "callback.html", gin.H{"error": false})
	}
}

func determineUserEmail(client *github.Client, user *github.User, c *gin.Context) string {
	if user.Email != nil {
		return *user.Email
	}

	emails, _, err := client.Users.ListEmails(c, nil)
	if err == nil && len(emails) > 0 {
		for _, email := range emails {
			if email.Primary != nil && *email.Primary {
				return *email.Email
			}
		}
	}

	return fmt.Sprintf("%s@users.noreply.github.com", *user.Login)
}

func handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func handleGetContributions(c *gin.Context) {
	session := sessions.Default(c)
	userSession := session.Get("user").(*UserSession)

	client := createGitHubClient(userSession.AccessToken)
	to := time.Now()
	from := getStartDateForContributions(to)

	contributions, err := fetchGitHubContributions(c, client, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, contributions)
}

func getStartDateForContributions(to time.Time) time.Time {
	from := to.AddDate(-1, 0, 0)
	for from.Weekday() != time.Sunday {
		from = from.AddDate(0, 0, -1)
	}
	return from
}

func createGitHubClient(token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return github.NewClient(tc)
}

func fetchGitHubContributions(c *gin.Context, client *github.Client, from, to time.Time) ([]ContributionDay, error) {
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

	variables := map[string]interface{}{
		"from": from.Format(time.RFC3339),
		"to":   to.Format(time.RFC3339),
	}

	req, err := client.NewRequest("POST", "graphql", map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	var response map[string]interface{}
	_, err = client.Do(c.Request.Context(), req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contributions: %v", err)
	}

	return parseContributionsResponse(response)
}

func parseContributionsResponse(response map[string]interface{}) ([]ContributionDay, error) {
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

	return contributions, nil
}

func handleCreateCommits(c *gin.Context) {
	session := sessions.Default(c)
	userSession := session.Get("user").(*UserSession)

	var req CommitPattern
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client := createGitHubClient(userSession.AccessToken)
	repoPath := filepath.Join(os.TempDir(), "commit-canvas", userSession.Username, req.RepoName)
	defer os.RemoveAll(filepath.Dir(repoPath))

	repo, err := setupRepository(c, client, userSession, req.RepoName, repoPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := createCommitPattern(repo, userSession, req.Pattern); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commits created successfully"})
}

func setupRepository(c *gin.Context, client *github.Client, userSession *UserSession, repoName, repoPath string) (*git.Repository, error) {
	os.RemoveAll(repoPath)

	remoteURL := fmt.Sprintf("https://%s:%s@github.com/%s/%s.git",
		userSession.Username, userSession.AccessToken, userSession.Username, repoName)
	auth := &githttp.BasicAuth{
		Username: userSession.Username,
		Password: userSession.AccessToken,
	}

	repo, err := git.PlainClone(repoPath, false, &git.CloneOptions{URL: remoteURL, Auth: auth})
	if err != nil {
		return initializeNewRepository(c, client, userSession, repoName, repoPath, remoteURL, auth)
	}

	return repo, nil
}

func initializeNewRepository(c *gin.Context, client *github.Client, userSession *UserSession, repoName, repoPath, remoteURL string, auth *githttp.BasicAuth) (*git.Repository, error) {
	if err := createGitHubRepository(c, client, repoName); err != nil {
		return nil, err
	}

	repo, err := git.PlainInit(repoPath, false)
	if err != nil {
		return nil, fmt.Errorf("failed to init repo: %v", err)
	}

	if err := setupInitialCommit(repo, userSession); err != nil {
		return nil, err
	}

	if err := setupRemoteAndPush(repo, remoteURL, auth); err != nil {
		return nil, err
	}

	return repo, nil
}

func createGitHubRepository(c *gin.Context, client *github.Client, repoName string) error {
	_, _, err := client.Repositories.Create(c, "", &github.Repository{
		Name:        github.String(repoName),
		Private:     github.Bool(false),
		AutoInit:    github.Bool(false),
		Description: github.String("Created by Commit Canvas"),
	})
	if err != nil {
		return fmt.Errorf("failed to create repository: %v", err)
	}
	return nil
}

func setupInitialCommit(repo *git.Repository, userSession *UserSession) error {
	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %v", err)
	}

	if err := createInitialFiles(w); err != nil {
		return err
	}

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  userSession.Username,
			Email: userSession.Email,
			When:  time.Now(),
		},
	})

	return err
}

func createInitialFiles(w *git.Worktree) error {
	if err := os.WriteFile(
		filepath.Join(w.Filesystem.Root(), "README.md"),
		[]byte(readmeContent),
		0644,
	); err != nil {
		return fmt.Errorf("failed to create README: %v", err)
	}

	_, err := w.Add("README.md")
	return err
}

func setupRemoteAndPush(repo *git.Repository, remoteURL string, auth *githttp.BasicAuth) error {
	_, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	if err != nil {
		return fmt.Errorf("failed to create remote: %v", err)
	}

	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/commit-canvas:refs/heads/commit-canvas")},
	})
	return err
}

func createCommitPattern(repo *git.Repository, userSession *UserSession, pattern [][]bool) error {
	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %v", err)
	}

	if err := w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(defaultBranch),
		Create: true,
		Force:  true,
	}); err != nil {
		return fmt.Errorf("failed to checkout branch: %v", err)
	}

	commitsDir := filepath.Join(w.Filesystem.Root(), "commits")
	if err := os.MkdirAll(commitsDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	startDate := getPatternStartDate()
	for col := 0; col < len(pattern); col++ {
		for row := 0; row < len(pattern[col]); row++ {
			if !pattern[col][row] {
				continue
			}

			commitDate := startDate.AddDate(0, 0, col*7+row)
			if err := createCommitFile(w, commitsDir, commitDate, userSession); err != nil {
				return err
			}
		}
	}

	return pushChanges(repo, userSession)
}

func getPatternStartDate() time.Time {
	startDate := time.Now().AddDate(-1, 0, 0)
	for startDate.Weekday() != time.Sunday {
		startDate = startDate.AddDate(0, 0, -1)
	}
	return startDate
}

func createCommitFile(w *git.Worktree, commitsDir string, commitDate time.Time, userSession *UserSession) error {
	fileName := fmt.Sprintf("commits/%s.txt", commitDate.Format("20060102150405"))
	filePath := filepath.Join(commitsDir, filepath.Base(fileName))

	content := fmt.Sprintf("Commit content generated at %s\n", commitDate.Format(time.RFC3339))
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	if _, err := w.Add(fileName); err != nil {
		return fmt.Errorf("failed to add file: %v", err)
	}

	_, err := w.Commit(fmt.Sprintf("Commit for %s", commitDate.Format("2006-01-02")), &git.CommitOptions{
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
	})
	return err
}

func pushChanges(repo *git.Repository, userSession *UserSession) error {
	auth := &githttp.BasicAuth{
		Username: userSession.Username,
		Password: userSession.AccessToken,
	}

	err := repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      true,
	})

	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("failed to push: %v", err)
	}

	return nil
}
