==============
Github Actions
==============

Aura provides an integration with the GitHub actions/ security view using the native sarif output format. Here is a minimal GitHub action configuration that scans the repository using Aura and uploads the generated SARIF report which can be viewed under the security tab of your repository:

::

    on: [push]
    jobs:
      aura_scan:
        runs-on: ubuntu-latest
        name: Scan the code with Aura
        steps:
          - name: aura scan
            id: aura_scan
            # This automatically generates the `aura_ci_report.sarif` file
            uses: SourceCode-AI/actions@master
          - name: Upload SARIF file
            uses: github/codeql-action/upload-sarif@v1
            with:
              sarif_file: aura_ci_report.sarif


Please be aware that you must first enable code scanning for your GitHub repository as this functionality is currently in beta and not available by default, otherwise the GitHub action will fail with a 403 - Forbidden error.

https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/enabling-code-scanning-for-a-repository
https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/sarif-support-for-code-scanning


==========
GitHub API
==========

When scanning or analyzing a package, Aura utilizes GitHub API to pull source repository metadata for (mainly) calculating the Aura score of the package. GitHub imposes a quite strict rate limit for the anonymous requests which would get depleted very quickly, for this reason, it is highly recommended to generate a private API access token that Aura can use as it raises the API limit significantly.

To get started, use the official tutorial to generate the API key: https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token . Aura needs read-only permission to read repository metadata such as the number of starts, last time of a commit, etc... (generic repo information) and a list of contributors for the repository. To access this data, aura needs the `repo` access permission.


After the token is generated you need to configure aura to use it. There are two options:

- set the token as `github_api` in the API tokens YAML config section
- set the token as `AURA_GITHUB_API_TOKEN` environment variable


You can verify the setup by running the `aura info` command which will check if the GitHub API token is configured and validate it.

