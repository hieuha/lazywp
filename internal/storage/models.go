package storage

import "time"

// Metadata stored per downloaded plugin/theme version.
type Metadata struct {
	Slug            string          `json:"slug"`
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Version         string          `json:"version"`
	SHA256          string          `json:"sha256"`
	FileSize        int64           `json:"file_size"`
	DownloadURL     string          `json:"download_url"`
	DownloadedAt    time.Time       `json:"downloaded_at"`
	WPMetadata      WPMetadata      `json:"wp_metadata"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// WPMetadata holds WordPress-specific info from the API.
type WPMetadata struct {
	ActiveInstallations int    `json:"active_installations"`
	TestedUpTo          string `json:"tested_up_to"`
	RequiresPHP         string `json:"requires_php"`
	Author              string `json:"author"`
	LastUpdated         string `json:"last_updated"`
}

// Vulnerability represents a known security issue.
type Vulnerability struct {
	CVE                string   `json:"cve"`
	CVSS               float64  `json:"cvss"`
	Type               string   `json:"type"`
	Title              string   `json:"title"`
	Source             string   `json:"source"`
	AffectedVersions   string   `json:"affected_versions"`
	MinAffectedVersion string   `json:"min_affected_version,omitempty"`
	MaxAffectedVersion string   `json:"max_affected_version,omitempty"`
	FixedIn            string   `json:"fixed_in"`
	References         []string `json:"references,omitempty"`
}

// IndexEntry represents one item in the download index.
type IndexEntry struct {
	Slug         string    `json:"slug"`
	Type         string    `json:"type"`
	Version      string    `json:"version"`
	DownloadedAt time.Time `json:"downloaded_at"`
	HasVulns     bool      `json:"has_vulns"`
	FileSize     int64     `json:"file_size"`
}

// ErrorEntry records a failed download.
type ErrorEntry struct {
	Slug      string    `json:"slug"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
	Retries   int       `json:"retries"`
}
