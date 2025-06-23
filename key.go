package secretsengine

import "time"

// keyVersion represents a specific version of an encryption key
type keyVersion struct {
	Version     int       `json:"version"`
	Key         []byte    `json:"key"`
	CreatedTime time.Time `json:"created_time"`
}

// encryptionKey represents a versioned encryption key
type encryptionKey struct {
	Name                 string              `json:"name"`
	Type                 string              `json:"type"`
	CreatedTime          time.Time           `json:"created_time"`
	Versions             map[int]*keyVersion `json:"versions"`
	LatestVersion        int                 `json:"latest_version"`
	MinDecryptVersion    int                 `json:"min_decrypt_version"`
	MinEncryptVersion    int                 `json:"min_encrypt_version"`
	AllowPlaintextBackup bool                `json:"allow_plaintext_backup"`
	DeletionAllowed      bool                `json:"deletion_allowed"`
}
