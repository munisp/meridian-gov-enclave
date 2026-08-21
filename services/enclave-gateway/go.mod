module github.com/munisp/meridian-gov-enclave/services/enclave-gateway

go 1.23

require (
	github.com/munisp/meridian-gov-enclave/packages/httpx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/authx v0.0.0
	github.com/munisp/meridian-gov-enclave/packages/keyx v0.0.0
)

replace (
	github.com/munisp/meridian-gov-enclave/packages/httpx => ../../packages/httpx
	github.com/munisp/meridian-gov-enclave/packages/authx => ../../packages/authx
	github.com/munisp/meridian-gov-enclave/packages/keyx => ../../packages/keyx
)
