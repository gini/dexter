## release workflow

We use a combination of [GitHub Actions](https://docs.github.com/en/actions) and [goreleaser](https://goreleaser.com/)

Configurations for those shouldn't generally require adjusting, but if they do, they are found underneath `.github` and `.goreleaser.yml`

In order to release:

1) Merge your changes to master
2) Push a tag following semVer. If you are unsure of what version to assign, you can find the concepts described here: https://semver.org/
3) Verify the github action defined in .github/ completed and a new release is available. You can see the status in the github web UI.

