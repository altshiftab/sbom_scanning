package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/altshiftab/sbom_scanning/pkg/database"
)

// databaseStaleAfter is how old a database may get before its age is pointed out.
const databaseStaleAfter = 48 * time.Hour

// defaultDatabaseDir is where Trivy itself keeps the database, so an existing one is reused.
func defaultDatabaseDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".", "trivy-db")
	}
	return filepath.Join(cacheDir, "trivy", "db")
}

// databaseAge tells how old the database in dir is, from its metadata; zero when unknown.
func databaseAge(dir string, now time.Time) time.Duration {
	metadata, err := database.ReadMetadata(dir)
	if err != nil || metadata == nil {
		return 0
	}
	return now.Sub(metadata.UpdatedAt)
}
