module github.com/munisp/meridian-gov-enclave/services/jrb

go 1.23

require (
	github.com/munisp/meridian-gov-enclave/packages/authx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/eventx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/storex v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.1 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/twmb/franz-go v1.18.1 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.9.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/munisp/meridian-gov-enclave/packages/authx => ../../packages/authx

replace github.com/munisp/meridian-gov-enclave/packages/eventx => ../../packages/eventx

replace github.com/munisp/meridian-gov-enclave/packages/storex => ../../packages/storex
