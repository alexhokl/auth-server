package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
)

const throttleTestIP = "192.0.2.10"

// throttleTestStore returns a Redis throttle store backed by an in-memory
// Redis server.
func throttleTestStore(t *testing.T) (*redisThrottleStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &redisThrottleStore{client: client, prefix: "auth-rate-limit"}, mr
}

func throttleTestThrottle(t *testing.T, maxPerEmail, maxPerIP int) (*SignInThrottle, *miniredis.Miniredis) {
	t.Helper()
	store, mr := throttleTestStore(t)
	return newSignInThrottle(store, maxPerEmail, maxPerIP, 15*time.Minute), mr
}

// throttleRecordFailures records count failed sign-ins of email from ip.
func throttleRecordFailures(t *testing.T, throttle *SignInThrottle, email, ip string, count int) {
	t.Helper()
	for range count {
		assert.NoError(t, throttle.recordFailure(context.Background(), email, ip))
	}
}

// redisThrottleStore Tests

func TestRedisThrottleStore_CountOfMissingKey_ReturnsZero(t *testing.T) {
	store, _ := throttleTestStore(t)

	count, err := store.Count(context.Background(), "missing")

	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestRedisThrottleStore_Increment_CountsWithPrefixAndExpiry(t *testing.T) {
	store, mr := throttleTestStore(t)
	ctx := context.Background()

	first, err := store.Increment(ctx, "key", time.Minute)
	assert.NoError(t, err)
	second, err := store.Increment(ctx, "key", time.Minute)
	assert.NoError(t, err)
	count, err := store.Count(ctx, "key")
	assert.NoError(t, err)

	assert.Equal(t, int64(1), first)
	assert.Equal(t, int64(2), second)
	assert.Equal(t, int64(2), count)
	assert.True(t, mr.Exists("auth-rate-limit:key"))
	assert.Equal(t, time.Minute, mr.TTL("auth-rate-limit:key"))
}

func TestRedisThrottleStore_Increment_KeepsWindowOfExistingCounter(t *testing.T) {
	store, mr := throttleTestStore(t)
	ctx := context.Background()

	_, err := store.Increment(ctx, "key", time.Minute)
	assert.NoError(t, err)
	mr.FastForward(40 * time.Second)
	_, err = store.Increment(ctx, "key", time.Minute)
	assert.NoError(t, err)

	assert.Equal(t, 20*time.Second, mr.TTL("auth-rate-limit:key"))

	mr.FastForward(20 * time.Second)
	count, err := store.Count(ctx, "key")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestRedisThrottleStore_Reset_DeletesCounter(t *testing.T) {
	store, mr := throttleTestStore(t)
	ctx := context.Background()
	_, err := store.Increment(ctx, "key", time.Minute)
	assert.NoError(t, err)

	assert.NoError(t, store.Reset(ctx, "key"))

	assert.False(t, mr.Exists("auth-rate-limit:key"))
}

func TestRedisThrottleStore_WithoutPrefix_UsesKey(t *testing.T) {
	store, mr := throttleTestStore(t)
	store.prefix = ""

	_, err := store.Increment(context.Background(), "key", time.Minute)

	assert.NoError(t, err)
	assert.True(t, mr.Exists("key"))
}

func TestRedisThrottleStore_ServerDown_ReturnsErrors(t *testing.T) {
	store, mr := throttleTestStore(t)
	mr.Close()
	ctx := context.Background()

	_, countErr := store.Count(ctx, "key")
	_, incrementErr := store.Increment(ctx, "key", time.Minute)

	assert.Error(t, countErr)
	assert.Error(t, incrementErr)
}

// SignInThrottle Tests

func TestSignInThrottle_UnderLimits_IsNotBlocked(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 2)

	blocked, err := throttle.isBlocked(context.Background(), "user@test.com", throttleTestIP)

	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestSignInThrottle_EmailLimitReached_IsBlockedFromAnyIP(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 3)

	blocked, err := throttle.isBlocked(context.Background(), "USER@test.com ", "198.51.100.1")

	assert.NoError(t, err)
	assert.True(t, blocked)
}

func TestSignInThrottle_IPLimitReached_IsBlockedForAnyEmail(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	for _, email := range []string{"a@test.com", "b@test.com", "c@test.com", "d@test.com", "e@test.com"} {
		throttleRecordFailures(t, throttle, email, throttleTestIP, 1)
	}

	blocked, err := throttle.isBlocked(context.Background(), "f@test.com", throttleTestIP)

	assert.NoError(t, err)
	assert.True(t, blocked)
}

func TestSignInThrottle_WindowExpired_IsNotBlocked(t *testing.T) {
	throttle, mr := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 5)

	mr.FastForward(15 * time.Minute)
	blocked, err := throttle.isBlocked(context.Background(), "user@test.com", throttleTestIP)

	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestSignInThrottle_DisabledLimits_IsNeverBlocked(t *testing.T) {
	throttle, mr := throttleTestThrottle(t, 0, -1)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 10)

	blocked, err := throttle.isBlocked(context.Background(), "user@test.com", throttleTestIP)

	assert.NoError(t, err)
	assert.False(t, blocked)
	assert.Empty(t, mr.Keys())
}

func TestSignInThrottle_RecordSuccess_ResetsEmailButNotIP(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	ctx := context.Background()
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 3)

	assert.NoError(t, throttle.recordSuccess(ctx, "user@test.com"))

	emailCount, err := throttle.store.Count(ctx, signInFailureEmailKey("user@test.com"))
	assert.NoError(t, err)
	ipCount, err := throttle.store.Count(ctx, signInFailureIPKey(throttleTestIP))
	assert.NoError(t, err)
	assert.Equal(t, int64(0), emailCount)
	assert.Equal(t, int64(3), ipCount)
}

func TestSignInThrottle_RedisDown_ReturnsErrors(t *testing.T) {
	throttle, mr := throttleTestThrottle(t, 3, 5)
	mr.Close()
	ctx := context.Background()

	_, blockedErr := throttle.isBlocked(ctx, "user@test.com", throttleTestIP)

	assert.Error(t, blockedErr)
	assert.Error(t, throttle.recordFailure(ctx, "user@test.com", throttleTestIP))
	assert.Error(t, throttle.recordSuccess(ctx, "user@test.com"))
}

func TestNewSignInThrottle_UsesRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	throttle := NewSignInThrottle(mr.Addr(), "", "auth-rate-limit", 3, 5, time.Minute)

	assert.NoError(t, throttle.recordFailure(context.Background(), "user@test.com", throttleTestIP))

	assert.True(t, mr.Exists("auth-rate-limit:signin:fail:email:user@test.com"))
	assert.True(t, mr.Exists("auth-rate-limit:signin:fail:ip:"+throttleTestIP))
}

// isMaliciousRequest Tests

// throttleServe serves a request from throttleTestIP to a handler which
// reports whether the request is malicious.
func throttleServe(throttle *SignInThrottle, email string) bool {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var malicious bool
	handler := func(c *gin.Context) {
		malicious = isMaliciousRequest(c, email)
	}
	if throttle == nil {
		router.GET("/", handler)
	} else {
		router.GET("/", WithSignInThrottle(throttle), handler)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = throttleTestIP + ":1234"
	router.ServeHTTP(httptest.NewRecorder(), req)
	return malicious
}

func TestIsMaliciousRequest_NoThrottle_ReturnsFalse(t *testing.T) {
	assert.False(t, throttleServe(nil, "user@test.com"))
}

func TestIsMaliciousRequest_UnderLimit_ReturnsFalse(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 2)

	assert.False(t, throttleServe(throttle, "user@test.com"))
}

func TestIsMaliciousRequest_EmailLimitReached_ReturnsTrue(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", "198.51.100.1", 3)

	assert.True(t, throttleServe(throttle, "user@test.com"))
}

func TestIsMaliciousRequest_IPLimitReached_ReturnsTrue(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "other@test.com", throttleTestIP, 5)

	assert.True(t, throttleServe(throttle, "user@test.com"))
}

func TestIsMaliciousRequest_RedisDown_ReturnsFalse(t *testing.T) {
	throttle, mr := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "user@test.com", throttleTestIP, 3)
	mr.Close()

	assert.False(t, throttleServe(throttle, "user@test.com"))
}

func TestRecordSignIns_RedisDown_DoesNotPanic(t *testing.T) {
	throttle, mr := throttleTestThrottle(t, 3, 5)
	mr.Close()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", WithSignInThrottle(throttle), func(c *gin.Context) {
		recordFailedSignIn(c, "user@test.com")
		recordSuccessfulSignIn(c, "user@test.com")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
}

// Handler Tests

func TestSignIn_TooManyFailures_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, userTestEmail, throttleTestIP, 3)
	router, _ := userGetTestRouter()
	router.POST("/signin", WithSignInThrottle(throttle), SignIn)

	req := userFormRequest(http.MethodPost, "/signin", map[string]string{"email": userTestEmail})
	w := userServe(router, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestSignInPasswordChallenge_TooManyFailures_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, userTestEmail, throttleTestIP, 3)
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", WithSignInThrottle(throttle), SignInPasswordChallenge)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInPasswordChallenge_WrongPassword_RecordsFailure(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", WithSignInThrottle(throttle), SignInPasswordChallenge)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	req := userSignInChallengeRequest("/signin/challenge", "wrong password")
	req.RemoteAddr = throttleTestIP + ":1234"
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	emailCount, err := throttle.store.Count(context.Background(), signInFailureEmailKey(userTestEmail))
	assert.NoError(t, err)
	ipCount, err := throttle.store.Count(context.Background(), signInFailureIPKey(throttleTestIP))
	assert.NoError(t, err)
	assert.Equal(t, int64(1), emailCount)
	assert.Equal(t, int64(1), ipCount)
}

func TestSignInPasswordChallenge_Success_ResetsFailures(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, userTestEmail, throttleTestIP, 2)
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", WithSignInThrottle(throttle), SignInPasswordChallenge)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusCreated, w.Code)
	count, err := throttle.store.Count(context.Background(), signInFailureEmailKey(userTestEmail))
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestLoginChallenge_TooManyFailures_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, throttleTestIP, 3)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", WithSignInThrottle(throttle), fidoTestService(t).LoginChallenge)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_UserNotFound_RecordsFailure(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", WithSignInThrottle(throttle), fidoTestService(t).LoginChallenge)
	fidoExpectUserNotFound(mock, fidoTestEmail)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	count, err := throttle.store.Count(context.Background(), signInFailureEmailKey(fidoTestEmail))
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestLogin_TooManyFailures_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, throttleTestIP, 3)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)

	sessionValues := map[string]interface{}{
		sessionEmailKey:           fidoTestEmail,
		sessionWebAuthnSessionKey: fidoWebAuthnSessionJSON(t),
	}
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_ValidationFailure_RecordsFailure(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)
	fidoExpectGetUser(mock, fidoTestEmail, true, fidoCredentialRows(fidoTestEmail))

	sessionValues := map[string]interface{}{
		sessionEmailKey:           fidoTestEmail,
		sessionWebAuthnSessionKey: fidoWebAuthnSessionJSON(t),
	}
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	count, err := throttle.store.Count(context.Background(), signInFailureEmailKey(fidoTestEmail))
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
}
