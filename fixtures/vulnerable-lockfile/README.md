# Scanner self-test fixture

A lockfile that pins `lodash@4.17.15`, a version with a published prototype-pollution advisory
(CVE-2020-8203). CI scans this folder and fails unless the scanner reports that CVE, which proves
the dependency scan actually detects known issues. Nothing here is installed or run.
