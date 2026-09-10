package service

import (
	"context"
	"errors"
	"fmt"
)

const confirmationResendAction = "email-confirmation.resend"

// EmailConfirmationResender handles public confirmation-link requests without
// revealing whether an address belongs to an account.
type EmailConfirmationResender struct {
	confirmation *EmailConfirmationService
	limiter      *RateLimiter
}

// NewEmailConfirmationResender constructs resend behavior with its own rate
// limiter budget, independent from sign-in and other authentication actions.
func NewEmailConfirmationResender(confirmation *EmailConfirmationService, limiter *RateLimiter) (*EmailConfirmationResender, error) {
	if confirmation == nil || limiter == nil {
		return nil, ErrInvalidConfirmationConfig
	}
	return &EmailConfirmationResender{confirmation: confirmation, limiter: limiter}, nil
}

// Resend accepts a confirmation request without account enumeration. Unknown,
// already confirmed, guest, and malformed addresses return nil without mail.
func (s *EmailConfirmationResender) Resend(ctx context.Context, rawEmail string) error {
	if s == nil || s.confirmation == nil || s.confirmation.users == nil || s.limiter == nil {
		return ErrInvalidConfirmationConfig
	}
	if ctx == nil {
		return errors.New("service: nil confirmation resend context")
	}
	email, err := NormalizeEmail(rawEmail)
	if err != nil || email == "" {
		return nil
	}
	decision, err := s.limiter.Allow(confirmationResendAction, email)
	if err != nil {
		return fmt.Errorf("allow confirmation resend: %w", err)
	}
	if !decision.Allowed {
		return RateLimitError{RetryAfter: decision.RetryAfter}
	}

	user, err := s.confirmation.users.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("find confirmation resend user: %w", err)
	}
	if user.ID <= 0 || user.IsGuest || user.Email == nil || user.EmailVerifiedAt != nil {
		return nil
	}
	return s.confirmation.Issue(ctx, user.ID)
}
