# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]
### Added
### Changed

## [0.2.1.0] - 2023-02-17
### Changed
- Fix Show instances formatting, and add instances for Keypairs, thanks [@NicolasT](https://github.com/NicolasT)

## [0.2.0.1] - 2022-04-30
### Changed
- Relax version bounds on text and bytestring, thanks [@ysangkok](https://github.com/ysangkok)

## [0.2.0.0] - 2021-05-27
### Added
- All AEAD variants are now in saltine
- Key comparisons now use sodium_memcmp to prevent timing attacks
- Liberal use of Internal modules
- Benchmarks added
- Export Key/Nonce/… constructors from Internal module
- New password hashing module
- Show instances for most (all?) relevant data types
- Signature types for detached functions

### Changed
- newtype accessor functions added, keypairs are separate data types now instead
of tuples

## [0.1.1.1] - 2021-01-15
### Changed
- Fix for running tests in `cabal repl` (thanks [@timds])
- Allow newer profunctors

## [0.1.1.0] - 2020-02-29
### Added
- bindings to generichash (Blake2), thanks [@donatello](https://github.com/donatello)

### Changed
- Don't use `fail` in tests to fix compilation with GHC 8.8
- Windows install instructions added, thanks [@tmcl](https://github.com/tmcl)
