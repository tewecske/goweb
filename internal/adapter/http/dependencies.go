package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

var (
	ErrInvalidHTTPDependencies = errors.New("http: invalid service dependencies")
	ErrSessionAuthentication   = errors.New("http: session authentication failed")
)

// Dependencies contains consuming-side ports used by HTTP handlers. Concrete
// repositories and services are assembled by the application composition
// package and passed here by process startup.
type Dependencies struct {
	Users         UserFinder
	Sessions      SessionLookup
	SessionAdmin  SessionSignOut
	SessionCookie *middleware.SessionCookie

	SignUp  SignUpper
	SignIn  SignInner
	SignOut SignOuter

	ConfirmationIssuer   ConfirmationIssuer
	ConfirmationResender ConfirmationResender
	ConfirmationConsumer ConfirmationConsumer
	PasswordResetter     PasswordResetter
	PasswordResetterUse  PasswordResetterUse
	OAuth                OAuthAuthenticator
	OAuthProviders       OAuthProviderLister
	GuestCreator         GuestCreator
	GuestClaimer         GuestClaimer
	GuestRedeemer        GuestRedeemer
	GuestUpgrader        GuestUpgrader

	ProfileSettings  ProfileSettingsUpdater
	PasswordSettings PasswordSettingsUpdater
	LocaleSettings   LocaleSettingsUpdater
	ThemeUpdater     AccountThemeUpdater
	IdentityLister   IdentityLister
	IdentityUnlinker IdentityUnlinker
	IdentityLink     IdentityLinkStarter

	Groups       GroupUseCases
	GroupInvites GroupInviter
	JoinGroup    JoinRateLimitedGroupJoiner

	AdminAccounts       AdminAccountLister
	AdminAccountCreator AdminAccountCreator
	AdminAccountEditor  AdminAccountEditor
	AdminUserDetailer   AdminUserDetailer
	AdminSessionRevoker AdminSessionRevoker
	AdminConfirmation   AdminConfirmationManager
	AdminIdentity       AdminIdentityManager
	AdminLockout        AdminLockoutManager
	AdminAudit          AdminAuditReader
	AdminMaintenance    AdminMaintenanceRunner
	AdminAuditRecorder  AdminActionRecorder
	AdminSystemConfig   service.SystemConfigurationProvider
	AdminRuntime        AdminRuntimeProvider
	AdminDatastoreStats AdminDatastoreStatsReader
	AdminRateLimits     AdminRateLimitManager

	Usage middleware.UsageRecorder

	AdminUsage      AdminUsageReporter
	AdminSuspicious AdminSuspiciousReporter
}

// AdminAccountLister lists accounts for the administrator area.
type AdminAccountLister interface {
	List(context.Context, service.AdminUserQuery) (service.AdminUserPage, error)
}

// AdminAccountCreator provisions a confirmed account for an administrator.
type AdminAccountCreator interface {
	Create(context.Context, service.AdminActionContext, service.AdminAccountInput) (service.User, error)
}

// AdminAccountEditor reads, atomically updates, and deletes an account for an
// administrator.
type AdminAccountEditor interface {
	Find(context.Context, int64) (service.User, error)
	Update(context.Context, service.AdminActionContext, int64, service.AdminAccountUpdateInput) (service.User, error)
	Delete(context.Context, service.AdminActionContext, int64, int64) error
}

// AdminUserDetailer aggregates safe account diagnostics for an administrator.
type AdminUserDetailer interface {
	Detail(context.Context, int64) (service.AdminUserDetail, error)
}

// AdminSessionRevoker ends every active session for an account.
type AdminSessionRevoker interface {
	RevokeSessions(context.Context, service.AdminActionContext, int64) error
}

// AdminConfirmationManager confirms an address or sends a fresh confirmation
// link for an account.
type AdminConfirmationManager interface {
	ConfirmEmail(context.Context, service.AdminActionContext, int64) error
	SendConfirmation(context.Context, service.AdminActionContext, int64) error
}

// AdminIdentityManager removes a linked external identity from an account.
type AdminIdentityManager interface {
	RemoveIdentity(context.Context, service.AdminActionContext, int64, int64) error
}

// AdminLockoutManager reads and clears live lockout state for an account.
type AdminLockoutManager interface {
	Status(context.Context, service.User) (service.LockoutStatus, error)
	Clear(context.Context, service.AdminActionContext, service.User) error
}

// AdminAuditReader lists administrator action history.
type AdminAuditReader interface {
	List(context.Context, service.AuditQuery) (service.AuditPage, error)
}

// AdminActionRecorder stores a completed administrator action in the audit
// trail without exposing credentials.
type AdminActionRecorder interface {
	Record(context.Context, service.AuditRecord) error
}

// AdminMaintenanceRunner inspects and runs scheduled cleanup jobs.
type AdminMaintenanceRunner interface {
	RunOnce(context.Context) ([]service.MaintenanceRun, error)
	RunJob(context.Context, string) (service.MaintenanceRun, error)
	Status() []service.MaintenanceStatus
}

// AdminRuntimeProvider reports live runtime and migration facts.
type AdminRuntimeProvider interface {
	RuntimeInfo() service.RuntimeInfo
	Migrations(context.Context) ([]service.MigrationInfo, error)
}

// AdminDatastoreStatsReader reports safe aggregate data-store counts.
type AdminDatastoreStatsReader interface {
	Counts(context.Context) (service.DatastoreCounts, error)
}

// AdminRateLimitManager lists and clears live rate-limit budgets.
type AdminRateLimitManager interface {
	Overview() []service.RateLimitActionInfo
	Buckets(string) ([]service.RateLimitBucketInfo, error)
	ClearAction(context.Context, service.AdminActionContext, string) (int, error)
	ClearAll(context.Context, service.AdminActionContext) (int, error)
}

// AdminUsageReporter builds route usage reports for administrators.
type AdminUsageReporter interface {
	Report(context.Context, string, bool) (service.UsageReport, error)
}

// AdminSuspiciousReporter builds suspicious-account reports.
type AdminSuspiciousReporter interface {
	Report(context.Context, string) (service.SuspiciousReport, error)
}

// UserFinder resolves an account for an authenticated session.
type UserFinder interface {
	FindUserByID(context.Context, int64) (service.User, error)
}

// SessionLookup validates an opaque session credential.
type SessionLookup interface {
	Lookup(context.Context, string) (service.Session, error)
}

// SessionSignOut revokes one opaque session credential.
type SessionSignOut interface {
	SignOut(context.Context, string) error
}

// SignUpper creates password-backed accounts.
type SignUpper interface {
	SignUp(context.Context, service.SignUpInput) (service.SignUpResult, error)
}

// SignInner authenticates password-backed accounts.
type SignInner interface {
	SignIn(context.Context, service.SignInInput, string) (service.SignInResult, error)
}

// SignOuter revokes the current session.
type SignOuter interface {
	SignOut(context.Context, string) error
}

type ConfirmationIssuer interface {
	Issue(context.Context, int64) error
}

type ConfirmationResender interface {
	Resend(context.Context, string) error
}

type ConfirmationConsumer interface {
	Confirm(context.Context, string) error
}

type PasswordResetter interface {
	Request(context.Context, string) error
}

type PasswordResetterUse interface {
	Redeem(context.Context, string, string) error
}

type OAuthAuthenticator interface {
	Start(context.Context, string) (string, error)
	Callback(context.Context, string, string, string) (service.OAuthSignInResult, error)
}

type OAuthProviderLister interface {
	Names() []string
}

type GuestCreator interface {
	Create(context.Context, string, string) (service.GuestSessionResult, error)
}

type GuestClaimer interface {
	Issue(context.Context, int64) (service.GuestClaimCode, error)
}

type GuestRedeemer interface {
	Redeem(context.Context, string, string) (service.GuestSessionResult, error)
}

type GuestUpgrader interface {
	Upgrade(context.Context, int64, service.GuestUpgradeInput) (service.User, error)
}

// Validate checks dependencies needed by session-aware routes.
func (d Dependencies) Validate() error {
	if d.Users == nil || d.Sessions == nil || d.SessionAdmin == nil || d.SessionCookie == nil {
		return ErrInvalidHTTPDependencies
	}
	return nil
}

// SessionAuthenticator resolves an authenticated account from its opaque
// browser cookie. It never exposes the cookie value through Principal.
type SessionAuthenticator struct {
	users    UserFinder
	sessions SessionLookup
	cookie   *middleware.SessionCookie
}

// NewSessionAuthenticator constructs request authentication from explicit
// session and account ports.
func NewSessionAuthenticator(users UserFinder, sessions SessionLookup, cookie *middleware.SessionCookie) (*SessionAuthenticator, error) {
	if users == nil || sessions == nil || cookie == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &SessionAuthenticator{users: users, sessions: sessions, cookie: cookie}, nil
}

// Authenticate validates the current browser session and returns only safe
// account identity and authorization state.
func (a *SessionAuthenticator) Authenticate(ctx context.Context, request *http.Request) (middleware.Principal, error) {
	if a == nil || a.users == nil || a.sessions == nil || a.cookie == nil || ctx == nil || request == nil {
		return middleware.Principal{}, ErrSessionAuthentication
	}
	sessionID, ok := a.cookie.Read(request)
	if !ok {
		return middleware.Principal{}, middleware.ErrUnauthenticated
	}
	session, err := a.sessions.Lookup(ctx, sessionID)
	if err != nil {
		return middleware.Principal{}, middleware.ErrUnauthenticated
	}
	user, err := a.users.FindUserByID(ctx, session.UserID)
	if err != nil || user.ID != session.UserID {
		return middleware.Principal{}, ErrSessionAuthentication
	}
	return middleware.Principal{ID: strconv.FormatInt(user.ID, 10), IsAdmin: user.IsAdmin}, nil
}
