package service

import (
	"context"
	"errors"
	"testing"
)

func TestAdminUserQueryNormalizeBoundsValues(t *testing.T) {
	tests := []struct {
		name  string
		input AdminUserQuery
		want  AdminUserQuery
	}{
		{
			name:  "defaults",
			input: AdminUserQuery{},
			want:  AdminUserQuery{Sort: AdminSortCreatedAt, Direction: AdminDirectionDesc, Page: 1, Size: DefaultAdminPageSize},
		},
		{
			name:  "explicit values preserved",
			input: AdminUserQuery{Search: " alice ", Admin: "yes", Guest: "no", Confirmed: "yes", Sort: "email", Direction: "asc", Page: 3, Size: 25},
			want:  AdminUserQuery{Search: "alice", Admin: "yes", Guest: "no", Confirmed: "yes", Sort: "email", Direction: "asc", Page: 3, Size: 25},
		},
		{
			name:  "negative page and oversized size are bounded",
			input: AdminUserQuery{Page: -4, Size: 10_000},
			want:  AdminUserQuery{Sort: AdminSortCreatedAt, Direction: AdminDirectionDesc, Page: 1, Size: MaxAdminPageSize},
		},
		{
			name:  "unknown tri-state filters reset to all",
			input: AdminUserQuery{Admin: "maybe", Guest: "1", Confirmed: "true"},
			want:  AdminUserQuery{Sort: AdminSortCreatedAt, Direction: AdminDirectionDesc, Page: 1, Size: DefaultAdminPageSize},
		},
		{
			name:  "unsupported sort falls back to created_at",
			input: AdminUserQuery{Sort: "password_hash", Direction: "sideways"},
			want:  AdminUserQuery{Sort: AdminSortCreatedAt, Direction: AdminDirectionDesc, Page: 1, Size: DefaultAdminPageSize},
		},
		{
			name:  "id sort defaults to descending",
			input: AdminUserQuery{Sort: "id"},
			want:  AdminUserQuery{Sort: AdminSortID, Direction: AdminDirectionDesc, Page: 1, Size: DefaultAdminPageSize},
		},
		{
			name:  "text sort defaults to ascending",
			input: AdminUserQuery{Sort: "username"},
			want:  AdminUserQuery{Sort: AdminSortUsername, Direction: AdminDirectionAsc, Page: 1, Size: DefaultAdminPageSize},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.input.Normalize()
			if got != test.want {
				t.Fatalf("Normalize() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestAdminUserQueryNormalizeBoundsSearchLength(t *testing.T) {
	long := make([]rune, maxAdminSearchLength+50)
	for index := range long {
		long[index] = 'a'
	}
	got := (AdminUserQuery{Search: string(long)}).Normalize()
	if len([]rune(got.Search)) != maxAdminSearchLength {
		t.Fatalf("search length = %d, want %d", len([]rune(got.Search)), maxAdminSearchLength)
	}
}

func TestAdminUserQueryOffset(t *testing.T) {
	if got := (AdminUserQuery{Page: 1, Size: 20}).Offset(); got != 0 {
		t.Fatalf("Offset(page 1) = %d, want 0", got)
	}
	if got := (AdminUserQuery{Page: 3, Size: 20}).Offset(); got != 40 {
		t.Fatalf("Offset(page 3) = %d, want 40", got)
	}
	if got := (AdminUserQuery{Page: 0, Size: 20}).Offset(); got != 0 {
		t.Fatalf("Offset(page 0) = %d, want 0", got)
	}
}

func TestAdminSearchPatternEscapesWildcards(t *testing.T) {
	got := AdminSearchPattern(`50%_off\deal`)
	want := `%50\%\_off\\deal%`
	if got != want {
		t.Fatalf("AdminSearchPattern() = %q, want %q", got, want)
	}
}

func TestAdminAccountServiceListNormalizesAndCountsPages(t *testing.T) {
	repository := &adminUserRepositoryStub{total: 45}
	service, err := NewAdminAccountService(userRepositoryStub{}, repository)
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	page, err := service.List(context.Background(), AdminUserQuery{Size: 20})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if repository.received.Size != 20 || repository.received.Page != 1 {
		t.Fatalf("repository query = %+v, want normalized size 20 page 1", repository.received)
	}
	if page.Total != 45 || page.Pages != 3 {
		t.Fatalf("page = %+v, want total 45 pages 3", page)
	}
}

func TestAdminAccountServiceListRejectsMissingContext(t *testing.T) {
	service, err := NewAdminAccountService(userRepositoryStub{}, &adminUserRepositoryStub{})
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	//nolint:staticcheck // intentional nil context
	if _, err := service.List(nil, AdminUserQuery{}); err == nil {
		t.Fatal("List(nil) error = nil, want failure")
	}
}

func TestNewAdminAccountServiceRejectsMissingPorts(t *testing.T) {
	if _, err := NewAdminAccountService(nil, &adminUserRepositoryStub{}); !errors.Is(err, ErrNilUserRepository) {
		t.Fatalf("error = %v, want %v", err, ErrNilUserRepository)
	}
	if _, err := NewAdminAccountService(userRepositoryStub{}, nil); !errors.Is(err, ErrNilAdminUserRepository) {
		t.Fatalf("error = %v, want %v", err, ErrNilAdminUserRepository)
	}
}

type adminUserRepositoryStub struct {
	received AdminUserQuery
	total    int
	err      error
}

func (s *adminUserRepositoryStub) ListUsers(_ context.Context, query AdminUserQuery) (AdminUserPage, error) {
	s.received = query
	if s.err != nil {
		return AdminUserPage{}, s.err
	}
	return AdminUserPage{Total: s.total, Page: query.Page, Size: query.Size}, nil
}

type userRepositoryStub struct{}

func (userRepositoryStub) CreateUser(context.Context, User) (User, error)        { return User{}, nil }
func (userRepositoryStub) FindUserByID(context.Context, int64) (User, error)     { return User{}, nil }
func (userRepositoryStub) FindUserByEmail(context.Context, string) (User, error) { return User{}, nil }
func (userRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	return User{}, nil
}
func (userRepositoryStub) UpdateUser(context.Context, User, int64) (User, error) { return User{}, nil }
func (userRepositoryStub) DeleteUser(context.Context, int64, int64) error        { return nil }
