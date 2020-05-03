package introspect

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber"
)

var (
	errMalformedToken = errors.New("Missing or malformed token")
)

// Config holds the configuration for the middleware
type Config struct {
	// IntrospectionURL is introspection endpoint of OAuth server.
	// Required. Default: ""
	IntrospectionURL string

	// AuthScheme is the scheme of Authorization header.
	// Optional. Default: "Bearer"
	AuthScheme string

	// ContextKey is used to store token information into context.
	// Optional. Default: "user"
	ContextKey string

	// Scopes defines required scopes for authorization.
	// Optional. Default: nil
	Scopes []string

	// Audience defines required audience for authorization.
	// Optional. Default: nil
	Audience []string

	// Issuers defines required issuers for authorization.
	// Optional. Default: nil
	Issuers []string

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(c *fiber.Ctx) string { c.SendStatus(401) }
	Unauthorized func(*fiber.Ctx)

	// ScopeStrategy is a strategy for matching scopes.
	// Used when Scoped field has values.
	// Optional. Default: nil
	ScopeStrategy func([]string, string) bool

	// TokenLookup is a function that is used to look up token.
	// Optional. Default: TokenFromHeader
	TokenLookup func(*fiber.Ctx) string

	// ErrorHandler is a function for handling unexpected errors.
	// Optional. Default: func(c *fiber.Ctx, err error) string { c.SendStatus(500) }
	ErrorHandler func(*fiber.Ctx, error)

	// IntrospectionRequestHeaders is list of headers
	// that is send to introspection endpoint.
	// Optional. Default: nil
	IntrospectionRequestHeaders map[string]string

	client *http.Client
}

// Session represents token data and stores in context.
type Session struct {
	Subject string
	Extra   map[string]interface{}
}

type introspectionResult struct {
	Active    bool                   `json:"active"`
	Extra     map[string]interface{} `json:"ext"`
	Subject   string                 `json:"sub,omitempty"`
	Username  string                 `json:"username"`
	Audience  []string               `json:"aud"`
	TokenType string                 `json:"token_type"`
	Issuer    string                 `json:"iss"`
	ClientID  string                 `json:"client_id,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
}

// New creates an introspection middleware for use in Fiber
func New(config ...Config) func(*fiber.Ctx) {

	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}
	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}
	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c *fiber.Ctx) {
			c.SendStatus(fiber.StatusUnauthorized)
		}
	}
	if cfg.TokenLookup == nil {
		cfg.TokenLookup = TokenFromHeader(fiber.HeaderAuthorization, cfg.AuthScheme)
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) {
			if err == errMalformedToken {
				c.Status(fiber.StatusBadRequest)
				c.SendString(err.Error())
				return
			}
			c.SendStatus(fiber.StatusInternalServerError)
		}
	}

	cfg.client = &http.Client{
		Timeout: time.Millisecond * 500,
	}

	return func(c *fiber.Ctx) {

		token := cfg.TokenLookup(c)
		if token == "" {
			cfg.ErrorHandler(c, errMalformedToken)
			return
		}

		body := url.Values{"token": {token}}
		if cfg.ScopeStrategy == nil {
			body.Add("scope", strings.Join(cfg.Scopes, " "))
		}

		introspectReq, err := http.NewRequest(http.MethodPost, cfg.IntrospectionURL, strings.NewReader(body.Encode()))
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		for key, value := range cfg.IntrospectionRequestHeaders {
			introspectReq.Header.Set(key, value)
		}

		introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := cfg.client.Do(introspectReq)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			cfg.Unauthorized(c)
			return
		}

		var i introspectionResult
		if err := json.NewDecoder(resp.Body).Decode(&i); err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		if len(i.TokenType) > 0 && i.TokenType != "access_token" {
			cfg.Unauthorized(c)
			return
		}

		if !i.Active {
			cfg.Unauthorized(c)
			return
		}

		for _, audience := range cfg.Audience {
			if !contains(i.Audience, audience) {
				cfg.Unauthorized(c)
				return
			}
		}

		if len(cfg.Issuers) > 0 {
			if !contains(cfg.Issuers, i.Issuer) {
				cfg.Unauthorized(c)
				return
			}
		}

		if cfg.ScopeStrategy != nil {
			for _, scope := range cfg.Scopes {
				if !cfg.ScopeStrategy(strings.Split(i.Scope, " "), scope) {
					cfg.Unauthorized(c)
					return
				}
			}
		}

		if len(i.Extra) == 0 {
			i.Extra = make(map[string]interface{})
		}

		i.Extra["username"] = i.Username
		i.Extra["client_id"] = i.ClientID
		i.Extra["scope"] = i.Scope

		s := Session{
			Subject: i.Subject,
			Extra:   i.Extra,
		}

		c.Locals(cfg.ContextKey, s)

		c.Next()
	}
}

// TokenFromHeader returns a function that extracts token from the request header.
func TokenFromHeader(header string, authScheme string) func(*fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:]
		}
		return ""
	}
}

// TokenFromQuery returns a function that extracts token from the query string.
func TokenFromQuery(param string) func(*fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Query(param)
	}
}

// TokenFromParam returns a function that extracts token from the url param string.
func TokenFromParam(param string) func(*fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Params(param)
	}
}

// TokenFromCookie returns a function that extracts token from the named cookie.
func TokenFromCookie(name string) func(*fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Cookies(name)
	}
}

func contains(s []string, v string) bool {
	for _, vv := range s {
		if vv == v {
			return true
		}
	}
	return false
}
