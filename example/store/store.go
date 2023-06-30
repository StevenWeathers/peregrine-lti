package store

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

type Service struct {
	DB *pgx.Conn
}

func New(ctx context.Context, dbURL string) *Service {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}

	return &Service{
		DB: conn,
	}
}
