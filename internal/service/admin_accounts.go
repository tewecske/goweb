package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultAdminPageSize is used when a request omits a page size.
	DefaultAdminPageSize = 20
	// MaxAdminPageSize bounds every administrator list request.
	MaxAdminPageSize     = 100
	maxAdminSearchLength = 255
)

// Tri-state administrator list filters. The empty value keeps every row.
const (
	AdminFilterAll = ""
	AdminFilterYes = "yes"
	AdminFilterNo  = "no"
)

// Supported administrator list sort keys.
const (
	AdminSortCreatedAt   = "created_at"
	AdminSortID          = "id"
	AdminSortEmail       = "email"
	AdminSortUsername    = "username"
	AdminSortDisplayName = "display_name"
)

// Sort directions accepted from the URL.
const (
	AdminDirectionAsc  = "asc"
	AdminDirectionDesc = "desc"
)

var (
	// ErrInvalidAdminQuery identifies unusable administrator list input.
	ErrInvalidAdminQuery = errors.New("service: invalid admin query")
	// ErrNilAdminUserRepository identifies missing administrator list persistence.
	ErrNilAdminUserRepository = errors.New("service: nil admin user repository")
)

// AdminUserQuery is the bounded, server-validated account-list query. Page,
// size, sorting, and filter values are clamped by Normalize so a hostile URL
// cannot request unbounded work.
type AdminUserQuery struct {
	Search    string
	Admin     string
	Guest     string
	Confirmed string
	Sort      string
	Direction string
	Page      int
	Size      int
}

// AdminUserPage is one page of accounts plus its total count.
type AdminUserPage struct {
	Users []User
	Total int
	Page  int
	Size  int
	Pages int
}

// Normalize returns a copy with every field bounded to a supported value.
// Invalid values fall back to safe defaults instead of failing the request.
func (q AdminUserQuery) Normalize() AdminUserQuery {
	q.Search = normalizeAdminSearch(q.Search)
	q.Admin = normalizeAdminTriState(q.Admin)
	q.Guest = normalizeAdminTriState(q.Guest)
	q.Confirmed = normalizeAdminTriState(q.Confirmed)
	q.Sort = normalizeAdminSort(q.Sort)
	q.Direction = normalizeAdminDirection(q.Direction, q.Sort)
	if q.Page < 1 {
		q.Page = 1
	}
	if q.Size < 1 {
		q.Size = DefaultAdminPageSize
	}
	if q.Size > MaxAdminPageSize {
		q.Size = MaxAdminPageSize
	}
	return q
}

// Offset returns the zero-based row offset for the normalized page.
func (q AdminUserQuery) Offset() int {
	if q.Page < 1 {
		return 0
	}
	return (q.Page - 1) * q.Size
}

// AdminUserRepository lists accounts for the administrator area. Implementations
// must apply search, filters, sorting, and pagination in the data store.
type AdminUserRepository interface {
	ListUsers(context.Context, AdminUserQuery) (AdminUserPage, error)
}

// AdminActionContext identifies the acting administrator and request origin
// for one audited action. Origin is a safe client identifier, never a URL.
type AdminActionContext struct {
	ActorID int64
	Origin  string
}

// AdminAccountInput contains the values an administrator supplies when creating
// or editing an account. An empty password leaves the account without a
// password; on edit it keeps the existing password.
type AdminAccountInput struct {
	Email    string
	Password string
	IsAdmin  bool
}

// AdminAccountService owns administrator account use cases. It applies server
// side validation before every repository call.
type AdminAccountService struct {
	users      UserRepository
	adminUsers AdminUserRepository
	hasher     PasswordHashProvider
	auditor    AuditRecorder
}

// NewAdminAccountService constructs administrator account use cases with
// explicit account, list, password, and audit dependencies. The auditor is
// optional and never blocks an account action on a recording failure.
func NewAdminAccountService(users UserRepository, adminUsers AdminUserRepository, hasher PasswordHashProvider, auditor AuditRecorder) (*AdminAccountService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if adminUsers == nil {
		return nil, ErrNilAdminUserRepository
	}
	if hasher == nil {
		return nil, errors.New("service: nil admin password hasher")
	}
	return &AdminAccountService{users: users, adminUsers: adminUsers, hasher: hasher, auditor: auditor}, nil
}

// Create provisions a confirmed account with an optional password and
// administrator status. A supplied audit failure never undoes the creation.
func (s *AdminAccountService) Create(ctx context.Context, actor AdminActionContext, input AdminAccountInput) (User, error) {
	if s == nil || s.users == nil || s.adminUsers == nil || s.hasher == nil {
		return User{}, ErrInvalidAdminQuery
	}
	if ctx == nil {
		return User{}, errors.New("service: nil admin create context")
	}
	if actor.ActorID <= 0 {
		return User{}, ErrInvalidAdminQuery
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil || email == "" {
		return User{}, ErrInvalidEmail
	}
	var passwordHash *string
	if input.Password != "" {
		if err := ValidatePassword(input.Password); err != nil {
			return User{}, err
		}
		hash, err := s.hasher.Hash(input.Password)
		if err != nil {
			return User{}, err
		}
		passwordHash = &hash
	}
	now := time.Now().Unix()
	verifiedAt := now
	created, err := s.users.CreateUser(ctx, User{
		Email:           &email,
		PasswordHash:    passwordHash,
		IsAdmin:         input.IsAdmin,
		Theme:           defaultUserTheme,
		Locale:          defaultUserLocale,
		CreatedAt:       now,
		EmailVerifiedAt: &verifiedAt,
	})
	if err != nil {
		return User{}, err
	}
	if created.ID <= 0 {
		return User{}, ErrInvalidCreatedUser
	}
	created.PasswordHash = nil
	s.record(ctx, actor, AuditActionAccountCreated, created, email)
	return created, nil
}

// AdminAccountUpdateInput contains the editable fields for one account. An
// empty password keeps the current password; a supplied password replaces it.
type AdminAccountUpdateInput struct {
	Email    string
	Password string
	IsAdmin  bool
	Version  int64
}

// Find returns one account's safe detail for the administrator area.
func (s *AdminAccountService) Find(ctx context.Context, targetID int64) (User, error) {
	if s == nil || s.users == nil || s.adminUsers == nil {
		return User{}, ErrInvalidAdminQuery
	}
	if ctx == nil {
		return User{}, errors.New("service: nil admin find context")
	}
	if targetID <= 0 {
		return User{}, ErrInvalidAdminQuery
	}
	user, err := s.users.FindUserByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return User{}, ErrRecordNotFound
		}
		return User{}, err
	}
	return publicUser(user), nil
}

// Update atomically changes an account's email, administrator status, and
// optional password using the caller's expected revision. A stale revision is a
// conflict; a vanished account is not-found.
func (s *AdminAccountService) Update(ctx context.Context, actor AdminActionContext, targetID int64, input AdminAccountUpdateInput) (User, error) {
	if s == nil || s.users == nil || s.adminUsers == nil || s.hasher == nil {
		return User{}, ErrInvalidAdminQuery
	}
	if ctx == nil {
		return User{}, errors.New("service: nil admin update context")
	}
	if actor.ActorID <= 0 || targetID <= 0 || input.Version < 0 {
		return User{}, ErrInvalidAdminQuery
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil || email == "" {
		return User{}, ErrInvalidEmail
	}
	var passwordHash *string
	if input.Password != "" {
		if err := ValidatePassword(input.Password); err != nil {
			return User{}, err
		}
		hash, err := s.hasher.Hash(input.Password)
		if err != nil {
			return User{}, err
		}
		passwordHash = &hash
	}
	current, err := s.users.FindUserByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return User{}, ErrRecordNotFound
		}
		return User{}, err
	}
	current.Email = &email
	current.IsAdmin = input.IsAdmin
	if passwordHash != nil {
		current.PasswordHash = passwordHash
	}
	updated, err := s.users.UpdateUser(ctx, current, input.Version)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			return User{}, ErrRecordNotFound
		case errors.Is(err, ErrOptimisticLockConflict), errors.Is(err, ErrDuplicateEmail):
			return User{}, err
		default:
			return User{}, err
		}
	}
	updated.PasswordHash = nil
	s.record(ctx, actor, AuditActionAccountUpdated, updated, email)
	return updated, nil
}

// record stores one administrator action as a best-effort audit event. A
// recording failure must not undo the completed account action.
func (s *AdminAccountService) record(ctx context.Context, actor AdminActionContext, action string, target User, detail string) {
	if s == nil || s.auditor == nil {
		return
	}
	record := AuditRecord{
		ActorUserID: actor.ActorID,
		Action:      action,
		TargetType:  "user",
		TargetID:    strconv.FormatInt(target.ID, 10),
		Detail:      detail,
		IP:          actor.Origin,
	}
	if actorUser, err := s.users.FindUserByID(ctx, actor.ActorID); err == nil && actorUser.Email != nil {
		record.ActorEmail = *actorUser.Email
	}
	_ = s.auditor.Record(ctx, record)
}

// List returns one bounded page of accounts.
func (s *AdminAccountService) List(ctx context.Context, query AdminUserQuery) (AdminUserPage, error) {
	if s == nil || s.users == nil || s.adminUsers == nil {
		return AdminUserPage{}, ErrInvalidAdminQuery
	}
	if ctx == nil {
		return AdminUserPage{}, errors.New("service: nil admin query context")
	}
	normalized := query.Normalize()
	page, err := s.adminUsers.ListUsers(ctx, normalized)
	if err != nil {
		return AdminUserPage{}, err
	}
	if page.Size < 1 {
		page.Size = normalized.Size
	}
	if page.Page < 1 {
		page.Page = normalized.Page
	}
	page.Pages = adminPageCount(page.Total, page.Size)
	return page, nil
}

func adminPageCount(total, size int) int {
	if total <= 0 || size <= 0 {
		return 0
	}
	return (total + size - 1) / size
}

func normalizeAdminSearch(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.ReplaceAll(trimmed, "\x00", "")
	if utf8.RuneCountInString(trimmed) <= maxAdminSearchLength {
		return trimmed
	}
	runes := []rune(trimmed)
	return string(runes[:maxAdminSearchLength])
}

func normalizeAdminTriState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AdminFilterYes:
		return AdminFilterYes
	case AdminFilterNo:
		return AdminFilterNo
	default:
		return AdminFilterAll
	}
}

func normalizeAdminSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AdminSortID:
		return AdminSortID
	case AdminSortEmail:
		return AdminSortEmail
	case AdminSortUsername:
		return AdminSortUsername
	case AdminSortDisplayName:
		return AdminSortDisplayName
	default:
		return AdminSortCreatedAt
	}
}

func normalizeAdminDirection(raw, sort string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AdminDirectionAsc:
		return AdminDirectionAsc
	case AdminDirectionDesc:
		return AdminDirectionDesc
	default:
		if sort == AdminSortCreatedAt || sort == AdminSortID {
			return AdminDirectionDesc
		}
		return AdminDirectionAsc
	}
}

// AdminSearchPattern escapes LIKE wildcards and wraps the term for a
// case-insensitive substring match.
func AdminSearchPattern(search string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search)
	return "%" + escaped + "%"
}
