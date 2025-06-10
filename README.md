# Commit Canvas

GitHub contribution graph pixel art generator. Creates custom patterns on your contribution graph through automated commit generation.

## Features

- GitHub OAuth authentication
- Real-time contribution graph preview
- Interactive pattern designer
- Automatic repository and commit creation
- Timezone-aware scheduling
- Private repository support

## Usage

Visit [commit-canvas.injun.dev](https://commit-canvas.injun.dev) to create patterns:

1. Login with GitHub
2. Click cells to design your pattern
3. Enter repository name
4. Click "Create Pattern"

The pattern will appear on your GitHub profile contribution graph within 24 hours.

## Local Development

Requirements:
- Go 1.23+
- GitHub OAuth App credentials

Setup:

```bash
git clone https://github.com/in-jun/commit-canvas.git
cd commit-canvas
go mod download

export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
export GITHUB_REDIRECT_URL="http://localhost:8080/callback"
export SESSION_SECRET="your_session_secret"

go run main.go
```

Access at `http://localhost:8080`

## Docker

```bash
docker build -t commit-canvas .
docker run -p 8080:8080 \
  -e GITHUB_CLIENT_ID="your_client_id" \
  -e GITHUB_CLIENT_SECRET="your_client_secret" \
  -e GITHUB_REDIRECT_URL="your_redirect_url" \
  -e SESSION_SECRET="your_session_secret" \
  commit-canvas
```

## Technical Details

Built with Go using Gin framework, go-git for Git operations, and GitHub OAuth for authentication. Commits are created in a dedicated `commit-canvas` branch with proper timestamps and content.

## License

MIT
