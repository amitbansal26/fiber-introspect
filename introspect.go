package introspect

import (
	introspection "github.com/arsmn/oauth2-introspection"
	"github.com/gofiber/fiber"
)

// Config holds the configuration for the middleware
type Config struct {
	introspection.Config

	// AuthScheme is the scheme of Authorization header.
	// Optional. Default: "Bearer"
	AuthScheme string

	// ContextKey is used to store token information into context.
	// Optional. Default: "user"
	ContextKey string

	// TokenLookup is a function that is used to look up token.
	// Optional. Default: TokenFromHeader
	TokenLookup func(*fiber.Ctx) string

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(c *fiber.Ctx) string { c.SendStatus(401) }
	Unauthorized func(*fiber.Ctx)

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(c *fiber.Ctx) string { c.SendStatus(403) }
	Forbidden func(*fiber.Ctx)

	// ErrorHandler is a function for handling unexpected errors.
	// Optional. Default: func(c *fiber.Ctx, err error) string { c.SendStatus(500) }
	ErrorHandler func(*fiber.Ctx, error)

	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: nil
	SuccessHandler func(*fiber.Ctx)

	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool
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

	if cfg.Forbidden == nil {
		cfg.Forbidden = func(c *fiber.Ctx) {
			c.SendStatus(fiber.StatusForbidden)
		}
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) {
			c.SendStatus(fiber.StatusInternalServerError)
		}
	}

	if cfg.TokenLookup == nil {
		cfg.TokenLookup = TokenFromHeader(fiber.HeaderAuthorization, cfg.AuthScheme)
	}

	var introspector = introspection.New(cfg.Config)
	return func(c *fiber.Ctx) {

		if cfg.Filter != nil && cfg.Filter(c) {
			c.Next()
			return
		}

		token := cfg.TokenLookup(c)
		result, err := introspector.Introspect(token)

		if err != nil {
			switch err {
			case introspection.ErrUnauthorized:
				cfg.Unauthorized(c)
			case introspection.ErrForbidden:
				cfg.Forbidden(c)
			default:
				cfg.ErrorHandler(c, err)
			}
			return
		}

		c.Locals(cfg.ContextKey, result)

		if cfg.SuccessHandler != nil {
			cfg.SuccessHandler(c)
		}

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
