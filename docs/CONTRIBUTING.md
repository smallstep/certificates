# Contributing to `step certificates`

We welcome contributions to `step certificates` of any kind including
documentation, themes, organization, tutorials, blog posts, bug reports,
issues, feature requests, feature implementations, pull requests, helping
to manage issues, etc.

## Table of Contents

* [Asking Support Questions](#asking-support-questions)
* [Reporting Issues](#reporting-issues)
* [Submitting Patches](#submitting-patches)
  * [Code Contribution Guidelines](#code-contribution-guidelines)
  * [Git Commit Message Guidelines](#git-commit-message-guidelines)

## Asking Support Questions

Users and developers can ask questions over email (info@smallstep.com) or
[twitter](https://twitter.com/smallsteplabs). Please don't use the GitHub
issue tracker to ask questions.

## Reporting Issues

If you believe you have found a defect in `step certificates` or its
documentation, use the GitHub [issue
tracker](https://github.com/smallstep/certificates/issues) to report the
problem. When reporting the issue, please provide the version of `step
certificates` in use (`step-ca version`) and your operating system.

## Code Contribution

`step certificates` aims to become a fully featured online Certificate
Authority. We encourage all contributions that meet the following criteria:

* fit naturally into a Certificate Authority.
* strive not to break existing functionality.
* close or update an open [`step certificates`
issue](https://github.com/smallstep/certificates/issues)

**Bug fixes are, of course, always welcome.**

## Submitting Patches

`step certificates` welcomes all contributors and contributions. If you are
interested in helping with the project, please reach out to us or, better yet,
submit a PR :).

### Code Contribution Guidelines

Because we want to create the best possible product for our users and the best
contribution experience for our developers, we have a set of guidelines which
ensure that all contributions are acceptable. The guidelines are not intended
as a filter or barrier to participation. If you are unfamiliar with the
contribution process, the Smallstep team will guide you in order to get your
contribution in accordance with the guidelines.

To make the contribution process as seamless as possible, we ask for the following:

* Go ahead and fork the project and make your changes. We encourage pull
requests to allow for review and discussion of code changes.
* When you’re ready to create a pull request, be sure to:
    * Sign the [CLA](https://cla-assistant.io/smallstep/certificates).
    * Have test cases for the new code. If you have questions about how to do
    this, please ask in your pull request.
    * Run `go fmt`.
    * Add documentation if you are adding new features or changing
    functionality.
    * Squash your commits into a single commit. `git rebase -i`. It’s okay to
    force update your pull request with `git push -f`.
    * Follow the **Git Commit Message Guidelines** below.

### Git Commit Message Guidelines

This [blog article](http://chris.beams.io/posts/git-commit/) is a good resource
for learning how to write good commit messages, the most important part being
that each commit message should have a title/subject in imperative mood
starting with a capital letter and no trailing period: *"Return error on wrong
use of the Paginator"*, **NOT** *"returning some error."*

Also, if your commit references one or more GitHub issues, always end your
commit message body with *See #1234* or *Fixes #1234*.  Replace *1234* with the
GitHub issue ID. The last example will close the issue when the commit is
merged into *master*.

Please use a short and descriptive branch name, e.g. **NOT** "patch-1". It's
very common but creates a naming conflict each time when a submission is pulled
for a review.

An example:

```text
Add step certificate install

Add a command line utility for installing (and uninstalling) certificates to the
local system truststores. This should help developers with local development
flows.

Fixes #75
```
