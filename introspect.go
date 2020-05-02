package introspect

import (
	"github.com/gofiber/fiber"
)

type Config struct {
	IntrospectionURL            string
	AuthScheme                  string
	ContextKey                  string
	Scopes                      []string
	Audience                    []string
	Issuers                     []string
	TokenLookup                 func(c *fiber.Ctx) string
	IntrospectionRequestHeaders map[string]string
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
	if cfg.TokenLookup == nil {
		cfg.TokenLookup = TokenFromHeader(fiber.HeaderAuthorization, cfg.AuthScheme)
	}

	return func(c *fiber.Ctx) {

	}
}

// TokenFromHeader returns a function that extracts token from the request header.
func TokenFromHeader(header string, authScheme string) func(c *fiber.Ctx) string {
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
func TokenFromQuery(param string) func(c *fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Query(param)
	}
}

// TokenFromParam returns a function that extracts token from the url param string.
func TokenFromParam(param string) func(c *fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Params(param)
	}
}

// TokenFromCookie returns a function that extracts token from the named cookie.
func TokenFromCookie(name string) func(c *fiber.Ctx) string {
	return func(c *fiber.Ctx) string {
		return c.Cookies(name)
	}
}
