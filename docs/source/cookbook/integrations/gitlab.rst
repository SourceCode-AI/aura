=========
GitLab CI
=========

Gitlab provides an integrated dashboard that can display SAST results and security details of your repository and track these metrics over time. Aura provides an integration with the native GitLab SAST support by including the scan that produces the SAST artifacts into your CI configuration. Here is a minimal example of scanning the current repository with Aura:


::

    image: docker:19.03.12

    variables:
      AURA_DOCKER_VERSION: "dev"

    services:
      - docker:19.03.12-dind

    aura_scan:
      tags:
        - docker  # Specify that this job can run only on CI runners that support docker
      stage: sast
      script:
        - docker run --rm -v ${CI_PROJECT_DIR}:/src:ro sourcecodeai/aura:${AURA_DOCKER_VERSION} scan /src -f gitlab-sast >${CI_PROJECT_DIR}/gl-aura-sast-report.json
      allow_failure: true  # Allow the CI pipeline to continue even if the Aura SAST scan fail
      artifacts:
        reports:
          sast: gl-aura-sast-report.json

    stages:
      - sast  # Run the stage that executes the aura scan job


The security dashboard and SAST scans were recently released by GitLab for free for public repositories. The CI integration would still work for private repositories but the access to the security dashboard is blocked if you do not have the gold (or higher) subscription.
