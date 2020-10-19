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
