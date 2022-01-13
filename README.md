# esp-coredump


## Python project
This template repo contains some useful tools common for Python projects. Tools have config files set according to Espressif project starndards.

### Pre-commit hooks - code quality
- flake8 for code style
- mypy type checker
- isort for sritng Python imports

... and more.
Set your additional pre-commit hooks in config file `.pre-commit-config.yaml`.
Lot of these tools are self-repairing, that means it not only tells you where is the problem but also suggests solution.

In `.gitlab-ci.yml` (project CI configuration) is already prepared job `codecheck`, which runs on every commit to master and evaluates code quality is accoding to Espressif code standards.

To avoid failing CI pipeline on code-check job is good idea install pre-commit hooks locally. Then code quality will be checked with every developers commit and adjusted continuosly.

> See https://pre-commit.com for more information


### Github actions for JIRA integrations
If this project is mirrored on Espressif Github, these actions allow integrate Espressif JIRA. With this turned on JIRA users will be notified about:
- Github issue comment
- Github project - new issue
- new Github pull request

> To make this work, on Github side some actions secrets must be set by Github project owner:
    - JIRA_URL
    - JIRA_USER
    - JIRA_PASS

