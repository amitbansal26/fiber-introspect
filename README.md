### Introspect
Introspection middleware for Fiber
Provides verifying an access token against a remote Introspection endpoint (RFC7662) 

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/arsmn/fiber-introspect
```

### Signature
```go
introspect.New(config ...introspect.Config) func(c *fiber.Ctx)
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| IntrospectionURL | `string` | Introspection endpoint url | `""` |
| AuthScheme | `string` | Scheme of Authorization header. | `"Bearer"` |
| ContextKey | `string` | ContextKey is used to store token information into context. | `"user"` |
| Scopes | `[]string` | Scopes defines required scopes for authorization. | `nil` |
| Audience | `[]string` | Audience defines required audience for authorization. | `nil` |
| Issuers | `[]string` | Issuers defines required issuers for authorization. | `nil` |
| ScopeStrategy | `func([]string, string) bool` | ScopeStrategy is a strategy for matching scopes. | `nil` |
| TokenLookup | `func(*fiber.Ctx) string` | TokenLookup is a function that is used to look up token. | `TokenFromHeader` |
| IntrospectionRequestHeaders | `map[string]string` | IntrospectionRequestHeaders is list of headers to send to introspection endpoint. | `nil` |
| Unauthorized | `func(*fiber.Ctx)` | Unauthorized defines a function which is executed when token is invalid | `401` |
| ErrorHandler | `func(*fiber.Ctx, error)` | ErrorHandler defines a function which is executed when an error occures. | `500 or 400 for malformed token` |
| SuccessHandler | `func([]string, string) bool` | SuccessHandler defines a function which is executed for a valid token. | `nil` |
| Filter | `func([]string, string) bool` | Filter defines a function to skip middleware | `nil` |

### Usage

```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/arsmn/fiber-introspect"
)

func main() {
  app := fiber.New()
  authz := introspect.New(introspect.Config{
      IntrospectionURL: "http://example.com/oauth/token",
  })

  app.Listen(8080)
}
```