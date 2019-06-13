# Distribution

This section describes how to build and deploy publicly available releases of
the Step CA.

## Creating A New Release

New releases are (almost) entirely built and deployed by Travis-CI. Creating a new
release is as simple as pushing a new github tag.

**Definitions**:

* **Standard Release**: ready for public use. no `-rc*` suffix on the version.
e.g. `v1.0.2`
* **Release Candidate**: not ready for public use, still testing. must have a
`-rc*` suffix. e.g. `v1.0.2-rc` or `v1.0.2-rc.4`

1. **Update the version of step/cli**

    ```
    $ dep ensure -update github.com/smallstep/cli
    ```

2. **Commit all changes.**

    Make sure that the local checkout is up to date with the remote origin and
    that all local changes have been pushed.

    ```
    $ git pull --rebase origin master
    $ git push
    ```

3. **Tag it!**

    1. **Find the most recent tag.**

        ```
        $ git fetch --tags
        $ git tag
        ```

        The new tag needs to be the logical successor of the most recent existing tag.
        See [versioning](#versioning) section for more information on version numbers.

    2. **Select the type and value of the next tag.**

        Is the new release a *release candidate* or a *standard release*?

        1. Release Candidate

            If the most recent tag is a standard release, say `v1.0.2`, then the version
            of the next release candidate should be `v1.0.3-rc.1`. If the most recent tag
            is a release candidate, say `v1.0.2-rc.3`, then the version of the next
            release candidate should be `v1.0.2-rc.4`.

        2. Standard Release

            If the most recent tag is a standard release, say `v1.0.2`, then the version
            of the next standard release should be `v1.0.3`. If the most recent tag
            is a release candidate, say `v1.0.2-rc.3`, then the version of the next
            standard release should be `v1.0.3`.


    3. **Create a local tag.**

        ```
        $ git tag v1.0.3   # standard release
        ...or
        $ git tag v1.0.3-rc.1  # release candidate
        ```

    4. **Push the new tag to the remote origin.**

        ```
        $ git push origin tag v1.0.3   # standard release
        ...or
        $ git push origin tag v1.0.3-rc.1  # release candidate
        ```

4. Check the build status at
[Travis-CI](https://travis-ci.com/smallstep/certificates/builds/).

    Travis will begin by verifying that there are no compilation or linting errors
    and then run the unit tests. Assuming all the checks have passed, Travis will
    build Darwin and Linux artifacts (for easily installing `step`) and upload them
    as part of the [Github Release](https://github.com/smallstep/certificates/releases).

    Travis will build and upload the following artifacts:

    * **step-certificates_1.0.3_amd64.deb**: debian package for installation on linux.
    * **step-certificates_1.0.3_linux_amd64.tar.gz**: tarball containing a statically compiled linux binary.
    * **step-certificates_1.0.3_darwin_amd64.tar.gz**: tarball containing a statically compiled darwin binary.
    * **step-certificates.tar.gz**: tarball containing a git archive of the full repo.

6. **Update the AUR Arch Linux package**

    > **NOTE**: if you plan to release `cli` next then you can skip this step.

    ```
    $ cd archlinux

    # Get up to date...
    $ git pull origin master
    $ make

    $ ./update --ca v1.0.3
    ```

7. **Update the Helm packages**

    > **NOTE**: This is an optional step, only necessary if we want to release a
    > new helm package.

    Once we have the docker images, we can release a new version in our Helm
    [repository](https://smallstep.github.io/helm-charts/) we need to pull the
    [helm-charts](https://github.com/smallstep/helm-charts) project, and change the
    following:

    * On step-certificates/Chart.yaml:
      * Increase the `version` number (Helm Chart version).
      * Set the `appVersion` to the step-certificates version.
    * On step-certificates/values.yaml:
      * Set the docker tag `image.tag` to the appropriate version.

    Then create the step-certificates package running:

    ```sh
    helm package ./step-certificates
    ```

    A new file like `step-certificates-<version>.tgz` would be created, then switch
    to the `gh-pages` branch and add the file to it, and update the index.yaml using
    the `helm repo index` command:

    ```sh
    git checkout gh-pages
    git add "step-certificates-<version>.tgz"
    helm repo index --merge index.yaml --url https://smallstep.github.io/helm-charts/ .
    git commit -a -m "Add package for step-certificates <appVersion>"
    git push origih gh-pages
    ```

*All Done!*

## Versioning

We use [SemVer](http://semver.org/) for versioning. See the
[tags on this repository](https://github.com/smallstep/certificates) for all
available versions.
