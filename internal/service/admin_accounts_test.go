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
	service, err := NewAdminAccountService(&userRepositoryStub{}, repository, adminPasswordHasherStub{}, nil)
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
	service, err := NewAdminAccountService(&userRepositoryStub{}, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, nil)
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	//nolint:staticcheck // intentional nil context
	if _, err := service.List(nil, AdminUserQuery{}); err == nil {
		t.Fatal("List(nil) error = nil, want failure")
	}
}

func TestNewAdminAccountServiceRejectsMissingPorts(t *testing.T) {
	if _, err := NewAdminAccountService(nil, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, nil); !errors.Is(err, ErrNilUserRepository) {
		t.Fatalf("error = %v, want %v", err, ErrNilUserRepository)
	}
	if _, err := NewAdminAccountService(&userRepositoryStub{}, nil, adminPasswordHasherStub{}, nil); !errors.Is(err, ErrNilAdminUserRepository) {
		t.Fatalf("error = %v, want %v", err, ErrNilAdminUserRepository)
	}
	if _, err := NewAdminAccountService(&userRepositoryStub{}, &adminUserRepositoryStub{}, nil, nil); err == nil {
		t.Fatal("missing hasher error = nil, want failure")
	}
}

func TestAdminAccountServiceCreateProvisionsConfirmedAccount(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9}}
	auditor := &auditRecorderStub{}
	service, err := NewAdminAccountService(users, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, auditor)
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	created, err := service.Create(context.Background(), AdminActionContext{ActorID: 1, Origin: "203.0.113.5"}, AdminAccountInput{
		Email:    " NewUser@Example.Test ",
		Password: "correct-horse-battery",
		IsAdmin:  true,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID != 9 || created.PasswordHash != nil {
		t.Fatalf("created = %+v, want id 9 without password hash", created)
	}
	sent := users.lastCreated
	if sent.Email == nil || *sent.Email != "newuser@example.test" {
		t.Fatalf("created email = %v, want normalized", sent.Email)
	}
	if sent.PasswordHash == nil || *sent.PasswordHash != "hash:correct-horse-battery" {
		t.Fatalf("created password hash = %v, want hashed value", sent.PasswordHash)
	}
	if !sent.IsAdmin || sent.EmailVerifiedAt == nil || *sent.EmailVerifiedAt != sent.CreatedAt {
		t.Fatalf("created = %+v, want confirmed administrator", sent)
	}
	if len(auditor.records) != 1 || auditor.records[0].Action != AuditActionAccountCreated {
		t.Fatalf("audit records = %+v, want one account-created record", auditor.records)
	}
	if auditor.records[0].TargetID != "9" || auditor.records[0].IP != "203.0.113.5" {
		t.Fatalf("audit record = %+v, want target 9 and origin", auditor.records[0])
	}
}

func TestAdminAccountServiceCreateAllowsMissingPassword(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9}}
	service, err := NewAdminAccountService(users, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, nil)
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	if _, err := service.Create(context.Background(), AdminActionContext{ActorID: 1}, AdminAccountInput{Email: "no-password@example.test"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if users.lastCreated.PasswordHash != nil {
		t.Fatalf("password hash = %v, want nil", users.lastCreated.PasswordHash)
	}
}

func TestAdminAccountServiceCreateAuditFailureDoesNotUndo(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9}}
	auditor := &auditRecorderStub{err: errors.New("audit storage down")}
	service, err := NewAdminAccountService(users, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, auditor)
	if err != nil {
		t.Fatalf("NewAdminAccountService() error = %v", err)
	}
	created, err := service.Create(context.Background(), AdminActionContext{ActorID: 1}, AdminAccountInput{Email: "a@example.test"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil despite audit failure", err)
	}
	if created.ID != 9 {
		t.Fatalf("created ID = %d, want 9", created.ID)
	}
}

func TestAdminAccountServiceCreateValidatesInput(t *testing.T) {
	tests := []struct {
		name  string
		actor AdminActionContext
		input AdminAccountInput
		want  error
	}{
		{name: "missing actor", input: AdminAccountInput{Email: "a@example.test"}, want: ErrInvalidAdminQuery},
		{name: "invalid email", actor: AdminActionContext{ActorID: 1}, input: AdminAccountInput{Email: "not-an-email"}, want: ErrInvalidEmail},
		{name: "missing email", actor: AdminActionContext{ActorID: 1}, input: AdminAccountInput{}, want: ErrInvalidEmail},
		{name: "weak password", actor: AdminActionContext{ActorID: 1}, input: AdminAccountInput{Email: "a@example.test", Password: "short"}, want: ErrPasswordTooShort},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &userRepositoryStub{created: User{ID: 9}}
			service, err := NewAdminAccountService(users, &adminUserRepositoryStub{}, adminPasswordHasherStub{}, nil)
			if err != nil {
				t.Fatalf("NewAdminAccountService() error = %v", err)
			}
			if _, err := service.Create(context.Background(), test.actor, test.input); !errors.Is(err, test.want) {
				t.Fatalf("Create() error = %v, want %v", err, test.want)
			}
			if users.createCalls != 0 {
				t.Fatal("CreateUser called for invalid input")
			}
		})
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

type userRepositoryStub struct {
	created     User
	createErr   error
	createCalls int
	lastCreated User
}

func (s *userRepositoryStub) CreateUser(_ context.Context, user User) (User, error) {
	s.createCalls++
	s.lastCreated = user
	if s.createErr != nil {
		return User{}, s.createErr
	}
	if s.created.ID == 0 {
		s.created = user
		s.created.ID = 9
	}
	return s.created, nil
}

func (s *userRepositoryStub) FindUserByID(_ context.Context, id int64) (User, error) {
	return User{ID: id, Email: strPtr("actor@example.test")}, nil
}
func (s *userRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	return User{}, nil
}
func (s *userRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	return User{}, nil
}
func (s *userRepositoryStub) UpdateUser(context.Context, User, int64) (User, error) {
	return User{}, nil
}
func (s *userRepositoryStub) DeleteUser(context.Context, int64, int64) error { return nil }

type adminPasswordHasherStub struct{ err error }

func (s adminPasswordHasherStub) Hash(password string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "hash:" + password, nil
}

type auditRecorderStub struct {
	records []AuditRecord
	err     error
}

func (s *auditRecorderStub) Record(_ context.Context, record AuditRecord) error {
	s.records = append(s.records, record)
	return s.err
}
