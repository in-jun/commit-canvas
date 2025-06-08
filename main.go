package main

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	Timezone    string
}

type ContributionDay struct {
	Date              string `json:"date"`
	ContributionCount int    `json:"contributionCount"`
}

type CommitPattern struct {
	Pattern  [][]bool `json:"pattern"`
	RepoName string   `json:"repoName"`
	Timezone string   `json:"timezone"`
}

// generateSessionSecret generates a secure session secret if not provided
func generateSessionSecret() []byte {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Println("Warning: SESSION_SECRET not set, generating random secret")
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			log.Fatal("Failed to generate session secret:", err)
		}
		return secretBytes
	}
	return []byte(secret)
}

// parseTimezone parses timezone from request header or returns UTC
func parseTimezone(c *gin.Context) string {
	tz := c.GetHeader("X-Timezone")
	if tz == "" {
		tz = "UTC"
	}

	// Try to validate timezone, but don't fail if timezone data is not available
	if _, err := time.LoadLocation(tz); err != nil {
		log.Printf("Timezone %s not available in this environment, will use UTC for calculations", tz)
		// Return the original timezone name for user display, but we'll handle calculations differently
	}

	return tz
}

func init() {
	gob.Register(&UserSession{})
}

func main() {
	// Validate required environment variables
	requiredEnvVars := []string{"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GITHUB_REDIRECT_URL"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("Required environment variable %s is not set", envVar)
		}
	}

	r := gin.Default()

	store := cookie.NewStore(generateSessionSecret())
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   strings.HasPrefix(os.Getenv("GITHUB_REDIRECT_URL"), "https://"),
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
		if code == "" {
			log.Println("No authorization code received")
			c.HTML(http.StatusBadRequest, "callback.html", gin.H{"error": true, "message": "No authorization code received"})
			return
		}

		token, err := oauth2Config.Exchange(c, code)
		if err != nil {
			log.Printf("Token exchange error: %v", err)
			c.HTML(http.StatusInternalServerError, "callback.html", gin.H{"error": true, "message": "Failed to exchange token"})
			return
		}

		client := github.NewClient(oauth2Config.Client(c, token))

		user, _, err := client.Users.Get(c, "")
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			c.HTML(http.StatusInternalServerError, "callback.html", gin.H{"error": true, "message": "Failed to get user information"})
			return
		}

		userSession := &UserSession{
			AccessToken: token.AccessToken,
			Username:    *user.Login,
			Timezone:    parseTimezone(c),
		}

		if user.Email != nil && *user.Email != "" {
			userSession.Email = *user.Email
		} else {
			emails, _, err := client.Users.ListEmails(c, nil)
			if err == nil && len(emails) > 0 {
				for _, email := range emails {
					if email.Primary != nil && *email.Primary && email.Email != nil {
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
			c.HTML(http.StatusInternalServerError, "callback.html", gin.H{"error": true, "message": "Failed to save session"})
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
	userSessionInterface := session.Get("user")
	if userSessionInterface == nil {
		log.Printf("No user session found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No user session"})
		return
	}

	userSession, ok := userSessionInterface.(*UserSession)
	if !ok {
		log.Printf("Invalid user session type: %T", userSessionInterface)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	log.Printf("Processing request for user: %s", userSession.Username)

	// First, let's test basic API access
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: userSession.AccessToken})
	tc := oauth2.NewClient(c, ts)
	client := github.NewClient(tc)

	// Test basic user access
	user, _, err := client.Users.Get(c, "")
	if err != nil {
		log.Printf("Failed to get user info for contributions: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "GitHub API access failed"})
		return
	}
	log.Printf("Fetching contributions for user: %s", *user.Login)

	// Get timezone preference
	timezone := c.Query("timezone")
	if timezone == "" {
		timezone = userSession.Timezone
	}
	if timezone == "" {
		timezone = "UTC"
	}

	log.Printf("Processing timezone: %s", timezone)

	// Try to load timezone, but gracefully fallback to UTC if not available
	loc := time.UTC
	if location, err := time.LoadLocation(timezone); err != nil {
		log.Printf("Timezone %s not available in this environment, using UTC for calculations", timezone)
	} else {
		loc = location
		log.Printf("Successfully loaded timezone: %s", timezone)
	}

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

	// Calculate date range to match GitHub's exact contribution graph
	// GitHub API only allows up to 1 year (365 days), so we use exactly 365 days
	now := time.Now().In(loc)

	// Calculate the start date: go back exactly 364 days (52 weeks) and find the Sunday
	startDate := now.AddDate(0, 0, -364)

	// Find the Sunday on or before this date
	for startDate.Weekday() != time.Sunday {
		startDate = startDate.AddDate(0, 0, -1)
	}

	// End date is today (to stay within 1 year limit)
	endDate := now

	from := startDate
	to := endDate.AddDate(0, 0, 1) // Include the day after end date for API call

	log.Printf("Date range: from %s to %s (duration: %v, timezone: %s)",
		from.Format("2006-01-02"), to.Format("2006-01-02"), to.Sub(from), timezone)

	variables := map[string]interface{}{
		"from": from.UTC().Format(time.RFC3339),
		"to":   to.UTC().Format(time.RFC3339),
	}

	log.Printf("GraphQL variables: %+v", variables)

	req, err := client.NewRequest("POST", "graphql", map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		log.Printf("Failed to create GraphQL request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	var response map[string]interface{}
	_, err = client.Do(c.Request.Context(), req, &response)
	if err != nil {
		log.Printf("Failed to fetch contributions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch contributions"})
		return
	}

	// Check for GraphQL errors first
	if errors, exists := response["errors"]; exists {
		log.Printf("GitHub GraphQL errors: %v", errors)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GitHub API returned errors"})
		return
	}

	// Debug: Check what we actually received
	if response["data"] == nil {
		log.Printf("GitHub API returned null data field")
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	// Parse response safely
	data, ok := response["data"].(map[string]interface{})
	if !ok {
		log.Printf("GitHub API data field is not a map, type: %T", response["data"])
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	viewer, ok := data["viewer"].(map[string]interface{})
	if !ok {
		log.Printf("Invalid response format: missing viewer")
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	collection, ok := viewer["contributionsCollection"].(map[string]interface{})
	if !ok {
		log.Printf("Invalid response format: missing contributionsCollection")
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	calendar, ok := collection["contributionCalendar"].(map[string]interface{})
	if !ok {
		log.Printf("Invalid response format: missing contributionCalendar")
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	weeks, ok := calendar["weeks"].([]interface{})
	if !ok {
		log.Printf("Invalid response format: missing weeks")
		c.JSON(http.StatusOK, []ContributionDay{})
		return
	}

	// Parse contribution data directly from GitHub's weeks structure
	// GitHub returns weeks in chronological order, each with 7 days (Sun-Sat)
	var contributions []ContributionDay

	// Initialize a map to store GitHub's contribution data by date
	contributionMap := make(map[string]int)

	// First, extract all contribution data from GitHub response into map
	for _, week := range weeks {
		weekData, ok := week.(map[string]interface{})
		if !ok {
			continue
		}

		days, ok := weekData["contributionDays"].([]interface{})
		if !ok {
			continue
		}

		for _, day := range days {
			dayData, ok := day.(map[string]interface{})
			if !ok {
				continue
			}

			dateStr, ok := dayData["date"].(string)
			if !ok {
				continue
			}

			contributionCount, ok := dayData["contributionCount"].(float64)
			if !ok {
				continue
			}

			contributionMap[dateStr] = int(contributionCount)
		}
	}

	// Now generate the grid exactly as frontend expects: 53 weeks × 7 days
	// Matching frontend calculation: col * 7 + row
	for col := 0; col < 53; col++ { // weeks
		for row := 0; row < 7; row++ { // days (0=Sunday, 6=Saturday)
			// Calculate the exact date for this grid cell
			cellDate := from.AddDate(0, 0, col*7+row)
			dateStr := cellDate.Format("2006-01-02")

			// Get contribution count from GitHub data, default to 0
			contributionCount := 0
			if count, exists := contributionMap[dateStr]; exists {
				contributionCount = count
			}

			contributions = append(contributions, ContributionDay{
				Date:              dateStr,
				ContributionCount: contributionCount,
			})

			// Debug log for verification (only log some samples)
			if col%10 == 0 && row == 0 {
				log.Printf("Grid[%d][%d]: Date %s, Contributions %d", col, row, dateStr, contributionCount)
			}
		}
	}

	c.JSON(http.StatusOK, contributions)
}

func createCommits(c *gin.Context) {
	session := sessions.Default(c)
	userSessionInterface := session.Get("user")
	if userSessionInterface == nil {
		log.Printf("No user session found in createCommits")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No user session"})
		return
	}

	userSession, ok := userSessionInterface.(*UserSession)
	if !ok {
		log.Printf("Invalid user session type in createCommits: %T", userSessionInterface)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	var req CommitPattern
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate request
	if req.RepoName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository name is required"})
		return
	}

	if len(req.Pattern) == 0 || len(req.Pattern[0]) != 7 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pattern must be a 2D array with 7 rows (days of week)"})
		return
	}

	// Get timezone
	timezone := req.Timezone
	if timezone == "" {
		timezone = userSession.Timezone
	}
	if timezone == "" {
		timezone = "UTC"
	}

	// Try to load timezone, but gracefully fallback to UTC if not available
	loc := time.UTC
	if location, err := time.LoadLocation(timezone); err != nil {
		log.Printf("Timezone %s not available in this environment, using UTC for calculations", timezone)
	} else {
		loc = location
		log.Printf("Successfully loaded timezone: %s", timezone)
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: userSession.AccessToken})
	tc := oauth2.NewClient(c, ts)
	client := github.NewClient(tc)

	// Validate repository name
	if !isValidRepoName(req.RepoName) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid repository name"})
		return
	}

	repoPath := filepath.Join(os.TempDir(), "commit-canvas", userSession.Username, req.RepoName)
	os.RemoveAll(repoPath)
	defer func() {
		if err := os.RemoveAll(filepath.Dir(repoPath)); err != nil {
			log.Printf("Failed to cleanup temp directory: %v", err)
		}
	}()

	remoteURL := fmt.Sprintf("https://%s:%s@github.com/%s/%s.git",
		userSession.Username, userSession.AccessToken, userSession.Username, req.RepoName)
	auth := &githttp.BasicAuth{
		Username: userSession.Username,
		Password: userSession.AccessToken,
	}

	var repo *git.Repository
	var w *git.Worktree
	var err error

	// Try to clone existing repository
	if repo, err = git.PlainClone(repoPath, false, &git.CloneOptions{
		URL:          remoteURL,
		Auth:         auth,
		SingleBranch: false,
	}); err != nil {
		// Repository doesn't exist or can't be cloned, check if it exists on GitHub
		if _, _, err = client.Repositories.Get(c, userSession.Username, req.RepoName); err != nil {
			// Repository doesn't exist, create it
			if _, _, err = client.Repositories.Create(c, "", &github.Repository{
				Name:        github.String(req.RepoName),
				Private:     github.Bool(false),
				AutoInit:    github.Bool(false),
				Description: github.String("Created by Commit Canvas - GitHub Contribution Graph Designer"),
			}); err != nil {
				log.Printf("Failed to create repository: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repository"})
				return
			}

			// Wait a moment for repository to be created
			time.Sleep(2 * time.Second)
		}

		// Initialize local repository
		if repo, err = git.PlainInit(repoPath, false); err != nil {
			log.Printf("Failed to init repo: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize repository"})
			return
		}

		// Create remote
		if _, err = repo.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: []string{remoteURL},
		}); err != nil {
			log.Printf("Failed to create remote: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create remote"})
			return
		}

		// Get worktree
		if w, err = repo.Worktree(); err != nil {
			log.Printf("Failed to get worktree: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get worktree"})
			return
		}

		// Create initial README
		readmeContent := fmt.Sprintf(`# %s

This repository was created by [Commit Canvas](https://github.com/in-jun/commit-canvas) - a tool for designing GitHub contribution graphs.

## About Commit Canvas

Commit Canvas allows you to create artistic patterns in your GitHub contribution graph by generating commits with specific dates.

Generated on: %s
`, req.RepoName, time.Now().In(loc).Format("2006-01-02 15:04:05 MST"))

		if err := os.WriteFile(
			filepath.Join(repoPath, "README.md"),
			[]byte(readmeContent),
			0644,
		); err != nil {
			log.Printf("Failed to create README: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create README"})
			return
		}

		if _, err := w.Add("README.md"); err != nil {
			log.Printf("Failed to add README: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add README"})
			return
		}

		// Create initial commit
		if _, err := w.Commit("Initial commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  userSession.Username,
				Email: userSession.Email,
				When:  time.Now().In(loc),
			},
			Committer: &object.Signature{
				Name:  userSession.Username,
				Email: userSession.Email,
				When:  time.Now().In(loc),
			},
		}); err != nil {
			log.Printf("Failed to commit: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create initial commit"})
			return
		}

		// Create and push commit-canvas branch
		headRef, err := repo.Head()
		if err != nil {
			log.Printf("Failed to get HEAD: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get HEAD reference"})
			return
		}

		ref := plumbing.NewHashReference(plumbing.NewBranchReferenceName("commit-canvas"), headRef.Hash())
		if err = repo.Storer.SetReference(ref); err != nil {
			log.Printf("Failed to set commit-canvas branch: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set commit-canvas branch"})
			return
		}

		// Push initial commit
		if err := repo.Push(&git.PushOptions{
			RemoteName: "origin",
			Auth:       auth,
			RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/commit-canvas:refs/heads/commit-canvas")},
		}); err != nil && err != git.NoErrAlreadyUpToDate {
			log.Printf("Failed to push initial commit: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to push initial commit"})
			return
		}
	}

	// Get worktree if not already obtained
	if w == nil {
		if w, err = repo.Worktree(); err != nil {
			log.Printf("Failed to get worktree: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get worktree"})
			return
		}
	}

	// Check if commit-canvas branch exists
	branches, _ := repo.Branches()
	branchExists := false
	branches.ForEach(func(branch *plumbing.Reference) error {
		if branch.Name().String() == "refs/heads/commit-canvas" {
			branchExists = true
		}
		return nil
	})

	// Checkout commit-canvas branch
	checkoutOpts := &git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName("commit-canvas"),
		Create: !branchExists,
		Force:  true,
	}

	if err := w.Checkout(checkoutOpts); err != nil {
		log.Printf("Failed to checkout commit-canvas branch: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to checkout commit-canvas branch"})
		return
	}

	// Create commits directory
	if err := os.MkdirAll(filepath.Join(repoPath, "commits"), 0755); err != nil {
		log.Printf("Failed to create commits directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create commits directory"})
		return
	}

	// Calculate start date - ensure it aligns with GitHub's contribution graph
	// and matches the same calculation used in getContributions
	now := time.Now().In(loc)

	// Calculate the start date: go back exactly 364 days (52 weeks) and find the Sunday
	startDate := now.AddDate(0, 0, -364)

	// Find the Sunday on or before this date
	for startDate.Weekday() != time.Sunday {
		startDate = startDate.AddDate(0, 0, -1)
	}

	log.Printf("Commit date range: from %s to %s (duration: %v)",
		startDate.Format("2006-01-02"), now.Format("2006-01-02"), now.Sub(startDate))

	// Create commits based on pattern
	// Pattern is organized as [week][day] where day 0 = Sunday
	for week := 0; week < len(req.Pattern); week++ {
		for day := 0; day < len(req.Pattern[week]); day++ {
			if !req.Pattern[week][day] {
				continue
			}

			commitDate := startDate.AddDate(0, 0, week*7+day)

			// Skip future dates
			if commitDate.After(now) {
				continue
			}

			fileName := fmt.Sprintf("commits/%s.txt", commitDate.Format("20060102_150405"))
			fileContent := fmt.Sprintf(`Commit Canvas - Contribution Graph Designer

Date: %s
Week: %d, Day: %d (%s)
Pattern Position: [%d][%d]

This commit was generated by Commit Canvas to create a pattern in the GitHub contribution graph.
Learn more: https://github.com/in-jun/commit-canvas

Generated at: %s
`,
				commitDate.Format("2006-01-02 15:04:05 MST"),
				week, day, commitDate.Weekday(),
				week, day,
				time.Now().In(loc).Format("2006-01-02 15:04:05 MST"))

			if err := os.WriteFile(
				filepath.Join(repoPath, fileName),
				[]byte(fileContent),
				0644,
			); err != nil {
				log.Printf("Failed to write file %s: %v", fileName, err)
				continue
			}

			if _, err := w.Add(fileName); err != nil {
				log.Printf("Failed to add file %s: %v", fileName, err)
				continue
			}

			if _, err := w.Commit(fmt.Sprintf("Commit Canvas: %s", commitDate.Format("2006-01-02")), &git.CommitOptions{
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
				log.Printf("Failed to commit for date %s: %v", commitDate.Format("2006-01-02"), err)
				continue
			}
		}
	}

	// Push all commits
	if err := repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      true,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		log.Printf("Failed to push commits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to push commits"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Commits created successfully",
		"repository": fmt.Sprintf("https://github.com/%s/%s", userSession.Username, req.RepoName),
		"branch":     "commit-canvas",
	})
}

// isValidRepoName validates GitHub repository name
func isValidRepoName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}

	// Basic validation for GitHub repository names
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.') {
			return false
		}
	}

	// Cannot start or end with special characters
	if name[0] == '-' || name[0] == '_' || name[0] == '.' ||
		name[len(name)-1] == '-' || name[len(name)-1] == '_' || name[len(name)-1] == '.' {
		return false
	}

	return true
}
