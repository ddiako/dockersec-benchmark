# Dockersec Benchmark

![Dockersec Benchmark running](https://raw.githubusercontent.com/ddiako/dockersec-benchmark/master/benchmark_log.png "Docker Bench for Security running")

The Dockersec Benchmark is a script that checks for dozens of common
best-practices around deploying Docker containers in production. The tests are
all automated, and are inspired by the [CIS Docker Community Edition Benchmark v1.1.0](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_Community_Edition_Benchmark_v1.1.0.pdf).

Dockersec Benchmark is partly based on docker-bench-security (https://github.com/docker/docker-bench-security).
The idea behind this fork is to add verbosity and mitigation to the different checks, as well as to improve
the scoring calculation and the categorization of the different tests.
According to that, some tests have been adapted to check differently the CIS points.

I thank diogomonica and konstruktoid for their excellent work on docker-bench-security.

This as an open-source utility so the Docker community
can have an easy way to self-assess their hosts and docker containers against
this benchmark.

## Running Dockersec Benchmark

This script can be run from your base host by running:

```sh
git clone https://github.com/ddiako/dockersec-benchmark.git
cd dockersec-benchmark
sudo sh dockersec-benchmark.sh
```

This script was built to be POSIX 2004 compliant, so it should be portable
across any Unix platform.

Dockersec benchmark requires Docker 1.13.0 or later in order to run.

Note that when distributions doesn't contain `auditctl`, the audit tests will
check `/etc/audit/audit.rules` to see if a rule is present instead.

### Dockersec Benchmark options

```sh
  -h           optional  Print this help message
  -l FILE      optional  Log output in FILE
  -c CHECK     optional  Comma delimited list of specific check(s)
  -e CHECK     optional  Comma delimited list of specific check(s) to exclude
  -x EXCLUDE   optional  Comma delimited list of patterns within a container name to exclude from check
```

By default the Dockersec Benchmark script will run all available CIS tests
and produce logs in the current directory named `dockersec-benchmark.sh.log.json`
and `dockersec-benchmark.sh.log`.
The CIS based checks are named `check_<section>_<number>`, e.g. `check_2_6`
and community contributed checks are named `check_c_<number>`.
A complete list of checks are present in [functions_lib.sh](functions_lib.sh).

`sh dockersec-benchmark.sh -l /tmp/dockersec-benchmark.sh.log -c check_2_2`

Note that when submitting checks, provide information why it is a
reasonable test to add and please include some kind of official documentation
verifying that information.

