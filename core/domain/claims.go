package domain

type Claims struct {
	UserID   string
	Role     string
	Metadata map[string]string
}
