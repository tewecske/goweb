package service

import (
	"context"
	"errors"
	"strings"
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

// AdminAccountService owns administrator account use cases. It applies server
// side validation before every repository call.
type AdminAccountService struct {
	users      UserRepository
	adminUsers AdminUserRepository
}

// NewAdminAccountService constructs administrator account use cases with
// explicit account and list persistence.
func NewAdminAccountService(users UserRepository, adminUsers AdminUserRepository) (*AdminAccountService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if adminUsers == nil {
		return nil, ErrNilAdminUserRepository
	}
	return &AdminAccountService{users: users, adminUsers: adminUsers}, nil
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
