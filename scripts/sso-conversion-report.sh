#!/bin/sh
# Dry run for converting an existing app (GOWEB_AUTH_MODE=local) to client
# mode: shows how each local account would be treated on its first single
# sign-on sign-in. It only reads: it creates session-local temporary objects
# that disappear on exit, and writes nothing to either database.
#
# Usage: scripts/sso-conversion-report.sh APP_DATABASE_URL PROVIDER_DATABASE_URL [--list]
#
# A local account is linked to its provider identity automatically only when
# the local account and the provider account have the same email and both
# addresses are verified. Everything else is refused at sign-in. Counts only by
# default; --list also prints the email addresses, so treat that output as
# personal data. Needs psql. Guests are ignored (they never convert by email).
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 APP_DATABASE_URL PROVIDER_DATABASE_URL [--list]" >&2
	exit 2
fi
app_url="$1"
provider_url="$2"
list="${3:-}"
if [ -n "$list" ] && [ "$list" != "--list" ]; then
	echo "unknown option: $list" >&2
	exit 2
fi

if [ -n "$list" ]; then
	report='SELECT category, email FROM classified WHERE category <> $$ready$$ ORDER BY category, email;'
else
	report='SELECT category, count(*) AS accounts FROM classified GROUP BY category ORDER BY category;'
fi

{
	echo "BEGIN;"
	echo "CREATE TEMP TABLE provider_emails (email text, verified boolean);"
	echo "COPY provider_emails FROM STDIN WITH (FORMAT csv);"
	psql -X -q -v ON_ERROR_STOP=1 "$provider_url" -c "\\copy (SELECT email, email_verified_at IS NOT NULL FROM users WHERE email IS NOT NULL AND NOT is_guest) TO STDOUT WITH (FORMAT csv)"
	echo '\.'
	cat <<SQL
CREATE TEMP VIEW classified AS
SELECT u.email,
       CASE
         WHEN p.email IS NULL THEN 'no_provider_account'
         WHEN u.email_verified_at IS NULL THEN 'local_email_unverified'
         WHEN NOT p.verified THEN 'provider_email_unverified'
         ELSE 'ready'
       END AS category
FROM users u
LEFT JOIN provider_emails p ON p.email = u.email
WHERE u.email IS NOT NULL AND NOT u.is_guest;
$report
ROLLBACK;
SQL
} | psql -X -q -v ON_ERROR_STOP=1 --pset=footer=off "$app_url"
