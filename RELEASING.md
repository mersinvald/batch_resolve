# Releasing

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://tools.ietf.org/html/bcp14) [RFC2119](https://tools.ietf.org/html/rfc2119) [RFC8174](https://tools.ietf.org/html/rfc8174) when, and only when, they appear in all capitals, as shown here.

This document is licensed under [The Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html).

When using the name 'version' we mean the versioning scheme described in [VERSIONING.md](VERSIONING.md)

## Introduction

This document is to describe the release pipeline, which is taking the result of the artifacts created by `cargo` and publish a release to the various platforms for the project.

We propose:
 - a set of release platform targets that are allowable
 - a pipeline for handling the release artifacts

It is NOT the purpose of this document to describe how a project might create a build, NOR is it describing a structure in which projects MUST write build artifacts to. It is describing the structure of the releases themselves.

## Release Pipeline

By default the project release pipeline is defined in the `.circleci/config.yml` and uses the `semantic-rs` tool for 
 - crates.io crate publishing
 - generating changelog from [semantic commits](CONVENTIONAL_COMMITS.md)
 - publishing a GitHub release
 
Documentation will automatically be available at [docs.rs](https://docs.rs) website after a few minutes since publishing a new release.

### Create a build from current branch

For building please follow the `cargo` [documentation](https://doc.rust-lang.org/cargo/index.html)

### Bump the version of the project

Projects SHOULD automate the version bump following [CONVENTIONAL_COMMITS.md](CONVENTIONAL_COMMITS.md).

### Generate Changelog

Projects SHOULD use generated changelogs from following [CONVENTIONAL_COMMITS.md](CONVENTIONAL_COMMITS.md).

### Commit the bump + changelog update

A project MUST generate a commit with the changes.

### Tag the commit with the bumped version

A project MUST be tagged with the semantic versioning scheme from [VERSIONING.md](VERSIONING.md).

### Sign the releases.

 - MUST be a pgp signature
 - MUST be the same pgp key as is registered with Github
 - MUST be a detached ascii-armored (.asc) signature 
 - All files in the build folder MUST have an associated signature file

### Push changelog & version bump

### Run Release Targets

For each of the desired release targets, prepare and push the release.

#### Example Release Targets

1. Github
2. [crates.io](https://crates.io)

## Resources

- [semantic-release](https://github.com/semantic-release/semantic-release)
- [Conventional Commits](https://conventionalcommits.org/)
