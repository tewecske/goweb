package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

func TestAuthenticationContract(t *testing.T) {
	store := newContractStore()
	hasher, err := service.NewPasswordHasher(service.PasswordHashConfig{
		Memory:     8 * 1024,
		Time:       1,
		Threads:    1,
		SaltLength: 16,
		KeyLength:  32,
	})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v, want nil", err)
	}
	sessions, err := service.NewSessionService(store, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}

	signup, err := service.NewSignUpService(store, hasher, sessions, false)
	if err != nil {
		t.Fatalf("NewSignUpService() error = %v, want nil", err)
	}
	signupResult, err := signup.SignUp(context.Background(), service.SignUpInput{
		Email:    " User@Example.COM ",
		Password: "correct horse battery staple",
		Username: "alice",
	})
	if err != nil {
		t.Fatalf("SignUp() error = %v, want nil", err)
	}
	if signupResult.User.PasswordHash != nil || signupResult.User.ID == 0 {
		t.Fatal("SignUp() returned password hash or missing user ID")
	}
	storedHash := store.users[signupResult.User.ID].PasswordHash
	if storedHash == nil || strings.Contains(*storedHash, "correct horse battery staple") {
		t.Fatal("stored password is missing hash or contains raw password")
	}

	cookie, err := middleware.NewSessionCookie(middleware.SessionCookieConfig{Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("NewSessionCookie() error = %v, want nil", err)
	}
	response := httptest.NewRecorder()
	if err := cookie.Set(response, signupResult.Session.ID, time.Now()); err != nil {
		t.Fatalf("SessionCookie.Set() error = %v, want nil", err)
	}
	if parsed := response.Result().Cookies()[0]; !parsed.HttpOnly || parsed.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie attributes = %#v, want HttpOnly/Lax", parsed)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Cookie", response.Header().Get("Set-Cookie"))
	if got, ok := cookie.Read(request); !ok || got != signupResult.Session.ID {
		t.Fatal("session cookie round trip failed")
	}

	attempts := &contractAttemptState{}
	signin, err := service.NewSignInService(store, hasher, sessions, attempts, false)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}
	limiter, err := service.NewRateLimiter(service.RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	limitedSignin, err := service.NewRateLimitedSignInService(signin, limiter)
	if err != nil {
		t.Fatalf("NewRateLimitedSignInService() error = %v, want nil", err)
	}
	input := service.SignInInput{Identifier: "ALICE", Password: "wrong-pass"}
	if _, err := limitedSignin.SignIn(context.Background(), input, "127.0.0.1"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatalf("wrong SignIn() error = %v, want invalid credentials", err)
	} else if strings.Contains(err.Error(), input.Password) {
		t.Fatal("wrong SignIn() error exposes password")
	}
	if _, err := limitedSignin.SignIn(context.Background(), input, "127.0.0.1"); !errors.Is(err, service.ErrRateLimited) {
		t.Fatalf("locked SignIn() error = %v, want rate limited", err)
	}
	limiter, err = service.NewRateLimiter(service.RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() fresh error = %v, want nil", err)
	}
	limitedSignin, err = service.NewRateLimitedSignInService(signin, limiter)
	if err != nil {
		t.Fatalf("NewRateLimitedSignInService() fresh error = %v, want nil", err)
	}
	signedIn, err := limitedSignin.SignIn(context.Background(), service.SignInInput{
		Identifier: "ALICE",
		Password:   "correct horse battery staple",
	}, "127.0.0.2")
	if err != nil {
		t.Fatalf("successful SignIn() error = %v, want nil", err)
	}
	if signedIn.User.PasswordHash != nil || attempts.cleared != "alice" {
		t.Fatal("successful SignIn() exposed hash or did not clear attempt state")
	}

	if err := sessions.SignOut(context.Background(), signedIn.Session.ID); err != nil {
		t.Fatalf("SignOut() error = %v, want nil", err)
	}
	if _, err := sessions.Lookup(context.Background(), signedIn.Session.ID); !errors.Is(err, service.ErrSessionRevoked) {
		t.Fatalf("Lookup(revoked) error = %v, want session revoked", err)
	}
	expiredID := "expired"
	store.sessions[expiredID] = service.Session{
		ID:        expiredID,
		UserID:    signupResult.User.ID,
		CreatedAt: time.Now().Unix() - 10,
		ExpiresAt: time.Now().Unix() - 1,
	}
	if _, err := sessions.Lookup(context.Background(), expiredID); !errors.Is(err, service.ErrSessionExpired) {
		t.Fatalf("Lookup(expired) error = %v, want session expired", err)
	}

	protected := middleware.RequireAuthenticated(contractAuthenticator{err: middleware.ErrUnauthenticated}, "/sign-in")(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)
	protectedResponse := httptest.NewRecorder()
	protected.ServeHTTP(protectedResponse, httptest.NewRequest(http.MethodGet, "/private", nil))
	if protectedResponse.Code != http.StatusFound || protectedResponse.Header().Get("Location") != "/sign-in" {
		t.Fatalf("protected redirect = %d/%q, want 302/sign-in", protectedResponse.Code, protectedResponse.Header().Get("Location"))
	}
	anonymous := middleware.RequireAnonymous(contractAuthenticator{}, "/home")(
		http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }),
	)
	anonymousResponse := httptest.NewRecorder()
	anonymous.ServeHTTP(anonymousResponse, httptest.NewRequest(http.MethodGet, "/sign-in", nil))
	if anonymousResponse.Code != http.StatusFound || anonymousResponse.Header().Get("Location") != "/home" {
		t.Fatalf("anonymous redirect = %d/%q, want 302/home", anonymousResponse.Code, anonymousResponse.Header().Get("Location"))
	}
}

type contractStore struct {
	nextUserID int64
	users      map[int64]service.User
	sessions   map[string]service.Session
}

func newContractStore() *contractStore {
	return &contractStore{
		nextUserID: 1,
		users:      make(map[int64]service.User),
		sessions:   make(map[string]service.Session),
	}
}

func (s *contractStore) CreateUser(_ context.Context, user service.User) (service.User, error) {
	user.ID = s.nextUserID
	s.nextUserID++
	s.users[user.ID] = user
	return user, nil
}

func (s *contractStore) FindUserByID(_ context.Context, id int64) (service.User, error) {
	user, ok := s.users[id]
	if !ok {
		return service.User{}, service.ErrUserNotFound
	}
	return user, nil
}

func (s *contractStore) FindUserByEmail(_ context.Context, email string) (service.User, error) {
	for _, user := range s.users {
		if user.Email != nil && *user.Email == email {
			return user, nil
		}
	}
	return service.User{}, service.ErrUserNotFound
}

func (s *contractStore) FindUserByUsername(_ context.Context, username string) (service.User, error) {
	for _, user := range s.users {
		if user.Username != nil && *user.Username == username {
			return user, nil
		}
	}
	return service.User{}, service.ErrUserNotFound
}

func (s *contractStore) UpdateUser(_ context.Context, user service.User, _ int64) (service.User, error) {
	s.users[user.ID] = user
	return user, nil
}

func (s *contractStore) DeleteUser(_ context.Context, id, _ int64) error {
	delete(s.users, id)
	return nil
}

func (s *contractStore) CreateSession(_ context.Context, session service.Session) error {
	s.sessions[session.ID] = session
	return nil
}

func (s *contractStore) FindSession(_ context.Context, id string) (service.Session, error) {
	session, ok := s.sessions[id]
	if !ok {
		return service.Session{}, service.ErrSessionNotFound
	}
	return session, nil
}

func (s *contractStore) RevokeSession(_ context.Context, id string, revokedAt int64) error {
	session, ok := s.sessions[id]
	if !ok {
		return service.ErrSessionNotFound
	}
	session.RevokedAt = &revokedAt
	s.sessions[id] = session
	return nil
}

func (s *contractStore) RevokeUserSessions(_ context.Context, userID int64) error {
	now := time.Now().Unix()
	for id, session := range s.sessions {
		if session.UserID == userID {
			session.RevokedAt = &now
			s.sessions[id] = session
		}
	}
	return nil
}

type contractAttemptState struct {
	cleared string
}

func (s *contractAttemptState) Clear(_ context.Context, identifier string) error {
	s.cleared = identifier
	return nil
}

type contractAuthenticator struct {
	err error
}

func (a contractAuthenticator) Authenticate(context.Context, *http.Request) (middleware.Principal, error) {
	if a.err != nil {
		return middleware.Principal{}, a.err
	}
	return middleware.Principal{ID: "user-1"}, nil
}
