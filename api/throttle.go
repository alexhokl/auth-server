package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

const contextKeySignInThrottle = "signin_throttle"

// throttleStore keeps counters which expire at the end of a window.
type throttleStore interface {
	Count(ctx context.Context, key string) (int64, error)
	Increment(ctx context.Context, key string, window time.Duration) (int64, error)
	Reset(ctx context.Context, key string) error
}

// redisThrottleStore keeps counters in Redis under keys with a prefix.
type redisThrottleStore struct {
	client *redis.Client
	prefix string
}

func (s *redisThrottleStore) key(key string) string {
	if s.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", s.prefix, key)
}

func (s *redisThrottleStore) Count(ctx context.Context, key string) (int64, error) {
	count, err := s.client.Get(ctx, s.key(key)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return count, err
}

// incrementScript increments a counter and starts its window when the counter
// is new, so that the window of an existing counter stays fixed.
var incrementScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
`)

func (s *redisThrottleStore) Increment(ctx context.Context, key string, window time.Duration) (int64, error) {
	return incrementScript.Run(ctx, s.client, []string{s.key(key)}, window.Milliseconds()).Int64()
}

func (s *redisThrottleStore) Reset(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.key(key)).Err()
}

// SignInThrottle limits failed sign-in attempts per email address and per
// client IP address within a fixed window. A limit of zero or less disables
// it.
type SignInThrottle struct {
	store       throttleStore
	maxPerEmail int
	maxPerIP    int
	window      time.Duration
}

// NewSignInThrottle returns a throttle keeping its counters in Redis under
// keys prefixed with redisKeyPrefix.
func NewSignInThrottle(redisHost, redisPassword, redisKeyPrefix string, maxPerEmail, maxPerIP int, window time.Duration) *SignInThrottle {
	client := redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: redisPassword,
	})
	return newSignInThrottle(
		&redisThrottleStore{client: client, prefix: redisKeyPrefix},
		maxPerEmail,
		maxPerIP,
		window,
	)
}

func newSignInThrottle(store throttleStore, maxPerEmail, maxPerIP int, window time.Duration) *SignInThrottle {
	return &SignInThrottle{
		store:       store,
		maxPerEmail: maxPerEmail,
		maxPerIP:    maxPerIP,
		window:      window,
	}
}

func signInFailureEmailKey(email string) string {
	return fmt.Sprintf("signin:fail:email:%s", strings.ToLower(strings.TrimSpace(email)))
}

func signInFailureIPKey(ip string) string {
	return fmt.Sprintf("signin:fail:ip:%s", ip)
}

// isBlocked returns true if either the email address or the IP address has
// reached its limit of failed sign-ins.
func (t *SignInThrottle) isBlocked(ctx context.Context, email, ip string) (bool, error) {
	if t.maxPerEmail > 0 && email != "" {
		count, err := t.store.Count(ctx, signInFailureEmailKey(email))
		if err != nil {
			return false, err
		}
		if count >= int64(t.maxPerEmail) {
			return true, nil
		}
	}
	if t.maxPerIP > 0 && ip != "" {
		count, err := t.store.Count(ctx, signInFailureIPKey(ip))
		if err != nil {
			return false, err
		}
		if count >= int64(t.maxPerIP) {
			return true, nil
		}
	}
	return false, nil
}

func (t *SignInThrottle) recordFailure(ctx context.Context, email, ip string) error {
	if t.maxPerEmail > 0 && email != "" {
		if _, err := t.store.Increment(ctx, signInFailureEmailKey(email), t.window); err != nil {
			return err
		}
	}
	if t.maxPerIP > 0 && ip != "" {
		if _, err := t.store.Increment(ctx, signInFailureIPKey(ip), t.window); err != nil {
			return err
		}
	}
	return nil
}

// recordSuccess resets the counter of the email address. The counter of the
// IP address is kept so that an attacker cannot reset it by signing in to an
// account of its own.
func (t *SignInThrottle) recordSuccess(ctx context.Context, email string) error {
	if t.maxPerEmail <= 0 || email == "" {
		return nil
	}
	return t.store.Reset(ctx, signInFailureEmailKey(email))
}

func WithSignInThrottle(throttle *SignInThrottle) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(contextKeySignInThrottle, throttle)
		c.Next()
	}
}

func getSignInThrottleFromContext(c *gin.Context) (*SignInThrottle, bool) {
	value, ok := c.Get(contextKeySignInThrottle)
	if !ok {
		return nil, false
	}
	throttle, ok := value.(*SignInThrottle)
	return throttle, ok && throttle != nil
}

// recordFailedSignIn counts a failed sign-in of email from the client IP
// address of the request.
func recordFailedSignIn(c *gin.Context, email string) {
	throttle, ok := getSignInThrottleFromContext(c)
	if !ok {
		return
	}
	if err := throttle.recordFailure(c.Request.Context(), email, c.ClientIP()); err != nil {
		slog.Error(
			"Unable to record failed sign-in",
			slog.String("error", err.Error()),
			slog.String("email", email),
		)
	}
}

// recordSuccessfulSignIn resets the count of failed sign-ins of email.
func recordSuccessfulSignIn(c *gin.Context, email string) {
	throttle, ok := getSignInThrottleFromContext(c)
	if !ok {
		return
	}
	if err := throttle.recordSuccess(c.Request.Context(), email); err != nil {
		slog.Error(
			"Unable to reset failed sign-ins",
			slog.String("error", err.Error()),
			slog.String("email", email),
		)
	}
}
