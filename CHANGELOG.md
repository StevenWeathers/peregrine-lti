# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2023-07-02

### Added
- [Go Documentation](https://pkg.go.dev/github.com/stevenweathers/peregrine-lti) reference to [README](README.md) under Getting Started
- Unit Tests for utility functions happy path

### Moved
- `GetLoginParamsFromRequestFormValues` from launch.Service public method to package public export
- `GetCallbackParamsFromRequestFormValues` from launch.Service public method to package public export
- `BuildLoginResponseRedirectURL` from launch.Service public method to package public export

### Removed
- Removed non-public utility and validation functions from launch Service struct

## [0.9.0] - 2023-07-02

### Added
- [Changelog](CHANGELOG.md) (this document!)
- Documentation for what why and example to readme
- CONTRIBUTING and CODE OF CONDUCT documentation
- GitHub Issue Templates
- GitHub Pull Request Template

## [0.8.1] - 2023-07-02

### Added
- Unit tests for `HandleOidcLogin` error handling

## [0.8.0] - 2023-07-02

### Added
- Rest of happy path unit tests for `HandleOidcLogin` and `HandleOidcCallback` methods

### Fixed
- Deployment ID validation to use platform deployment ID not internal data store ID

## [0.7.0] - 2023-07-01

### Added
- `golangci-lint` to GitHub actions workflow

## [0.6.0] - 2023-07-01

### Added
- Unit test for launch `HandleOidcLogin` happy path
- Unit test for launch `HandleOidcCallback` happy path

### Changed
- Launch errors to be more verbose
- Launch callback to return updated launch

## [0.5.0] - 2023-07-01

### Removed
- Dependency on platform instance and deployment being pre-populated in data storage service

## [0.4.0] - 2023-06-30

### Fixed
- `sub` claim value missing in `peregrine.LTI1p3Claims` struct

## [0.3.0] - 2023-06-29

### Added
- Utility functions to parse form values into login `peregrine.OIDCLoginRequestParams` and callback `peregrine.OIDCAuthenticationResponse` request structs

## [0.2.0] - 2023-06-29

### Added
- launch package BuildLoginResponseRedirectURL utility method

### Changed
- Wrap handler responses in response structs to allow future additions

### Fixed

- LTI spec claim conversion to `peregrine.LTI1p3Claims` struct
- Presentation claim height and width types from `string` to `int`

### Removed
- Remove dependence on platform instance being pre-populated in datasource

## [0.1.0] - 2023-06-29

### Added
- First iteration of the public `launch` package API
- First iteration of the public `peregrine` package domain (in `struct` form)