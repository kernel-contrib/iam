package migrations

import "embed"

// FS contains all SQL migration files for the IAM module.
// The kernel's migration runner reads from this filesystem.
//
//go:embed *.sql
var FS embed.FS
