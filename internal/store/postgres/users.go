package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tewecske/goweb/internal/service"
)

// UserRepository persists service users in PostgreSQL.
type UserRepository struct {
	adapter *Adapter
}

// NewUserRepository constructs a PostgreSQL user repository over db.
func NewUserRepository(db *sql.DB) (*UserRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &UserRepository{adapter: adapter}, nil
}

var _ service.UserRepository = (*UserRepository)(nil)

// CreateUser inserts one account and returns database-generated fields.
func (r *UserRepository) CreateUser(ctx context.Context, user service.User) (service.User, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.User{}, err
	}
	if user.Theme == "" {
		user.Theme = "light"
	}
	if user.Locale == "" {
		user.Locale = "en"
	}
	created, err := scanUser(db.QueryRowContext(ctx, `
		INSERT INTO users (
			email, password_hash, username, display_name, is_guest, is_admin,
			theme, locale, created_at, email_verified_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, email, password_hash, username, display_name, is_guest,
			is_admin, theme, locale, created_at, email_verified_at, version
	`, user.Email, user.PasswordHash, user.Username, user.DisplayName, user.IsGuest,
		user.IsAdmin, user.Theme, user.Locale, user.CreatedAt, user.EmailVerifiedAt, user.Version))
	if err != nil {
		return service.User{}, mapUserError(err)
	}
	return created, nil
}

// FindUserByID returns one account by its generated identifier.
func (r *UserRepository) FindUserByID(ctx context.Context, id int64) (service.User, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.User{}, err
	}
	if id <= 0 {
		return service.User{}, service.ErrUserNotFound
	}
	return r.find(ctx, db.QueryRowContext(ctx, userSelect+" WHERE id = $1", id))
}

// FindUserByEmail returns an account by normalized email.
func (r *UserRepository) FindUserByEmail(ctx context.Context, email string) (service.User, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.User{}, err
	}
	normalized, err := service.NormalizeEmail(email)
	if err != nil || normalized == "" {
		return service.User{}, service.ErrUserNotFound
	}
	return r.find(ctx, db.QueryRowContext(ctx, userSelect+" WHERE email = $1", normalized))
}

// FindUserByUsername returns an account by normalized username.
func (r *UserRepository) FindUserByUsername(ctx context.Context, username string) (service.User, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.User{}, err
	}
	normalized, err := service.NormalizeUsername(username)
	if err != nil || normalized == "" {
		return service.User{}, service.ErrUserNotFound
	}
	return r.find(ctx, db.QueryRowContext(ctx, userSelect+" WHERE username = $1", normalized))
}

// UpdateUser replaces editable account fields when expectedVersion is current.
func (r *UserRepository) UpdateUser(ctx context.Context, user service.User, expectedVersion int64) (service.User, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.User{}, err
	}
	updated, scanErr := scanUser(db.QueryRowContext(ctx, `
		UPDATE users
		SET email = $1, password_hash = $2, username = $3, display_name = $4,
			is_guest = $5, is_admin = $6, theme = $7, locale = $8,
			email_verified_at = $9, version = version + 1
		WHERE id = $10 AND version = $11
		RETURNING id, email, password_hash, username, display_name, is_guest,
			is_admin, theme, locale, created_at, email_verified_at, version
	`, user.Email, user.PasswordHash, user.Username, user.DisplayName, user.IsGuest,
		user.IsAdmin, user.Theme, user.Locale, user.EmailVerifiedAt,
		user.ID, expectedVersion))
	if scanErr == nil {
		return updated, nil
	}
	if !errors.Is(scanErr, sql.ErrNoRows) {
		return service.User{}, mapUserError(scanErr)
	}
	return service.User{}, r.classifyMissingWrite(ctx, db, user.ID)
}

// DeleteUser removes an account when expectedVersion is current.
func (r *UserRepository) DeleteUser(ctx context.Context, id, expectedVersion int64) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = $1 AND version = $2", id, expectedVersion)
	if err != nil {
		return mapUserError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return mapUserError(err)
	}
	if rows == 1 {
		return nil
	}
	return r.classifyMissingWrite(ctx, db, id)
}

const userSelect = `
	SELECT id, email, password_hash, username, display_name, is_guest,
		is_admin, theme, locale, created_at, email_verified_at, version
	FROM users`

type rowScanner interface {
	Scan(...any) error
}

func (r *UserRepository) find(ctx context.Context, row rowScanner) (service.User, error) {
	user, err := scanUser(row)
	if err != nil {
		return service.User{}, mapUserError(err)
	}
	return user, nil
}

func (r *UserRepository) classifyMissingWrite(ctx context.Context, db *sql.DB, id int64) error {
	if id <= 0 {
		return service.ErrUserNotFound
	}
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)", id).Scan(&exists)
	if err != nil {
		return mapUserError(err)
	}
	if !exists {
		return service.ErrUserNotFound
	}
	return service.ErrOptimisticLockConflict
}

func (r *UserRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}

func scanUser(row rowScanner) (service.User, error) {
	var (
		user                  service.User
		email, passwordHash   sql.NullString
		username, displayName sql.NullString
		emailVerifiedAt       sql.NullInt64
	)
	if err := row.Scan(
		&user.ID, &email, &passwordHash, &username, &displayName,
		&user.IsGuest, &user.IsAdmin, &user.Theme, &user.Locale,
		&user.CreatedAt, &emailVerifiedAt, &user.Version,
	); err != nil {
		return service.User{}, err
	}
	if user.ID <= 0 || user.Version < 0 {
		return service.User{}, ErrInvalidData
	}
	user.Email = nullableString(email)
	user.PasswordHash = nullableString(passwordHash)
	user.Username = nullableString(username)
	user.DisplayName = nullableString(displayName)
	user.EmailVerifiedAt = nullableInt64(emailVerifiedAt)
	return user, nil
}

func mapUserError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrNotFound) {
		return service.ErrUserNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "users_email_unique_idx":
			return service.ErrDuplicateEmail
		case "users_username_unique_idx":
			return service.ErrDuplicateUsername
		}
	}
	return ClassifyError(err)
}
