module github.com/munisp/meridian-gov-enclave/services/jrb

go 1.23

require (
	github.com/munisp/meridian-gov-enclave/packages/authx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/eventx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/storex v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/munisp/meridian-gov-enclave/packages/authx => ../../packages/authx
	github.com/munisp/meridian-gov-enclave/packages/eventx => ../../packages/eventx
	github.com/munisp/meridian-gov-enclave/packages/storex => ../../packages/storex
)
