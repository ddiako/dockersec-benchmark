#!/bin/sh
# ------------------------------------------------------------------------------
# Dockersec Benchmark for Security Enhanced
# by @ddiako (https://github.com/ddiako/dockersec-benchmark)
# 
# Checks for dozens of common best-practices around deploying Docker containers in production.
#
# Fork of docker-bench-security (https://github.com/docker/docker-bench-security)
# Benchmark inspired by the [CIS Docker Community Edition Benchmark v1.1.0]
# (https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_Community_Edition_Benchmark_v1.1.0.pdf)
# ------------------------------------------------------------------------------

version='1.3.4'

# Load dependencies
. ./functions_lib.sh
. ./helper_lib.sh
. ./output_lib.sh

# Setup the paths
this_path=$(abspath "$0")       ## Path of this file including filename
myname=$(basename "${this_path}")     ## file name of this script.

readonly version
readonly this_path
readonly myname

export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin/

# Check for required program(s)
req_progs='awk docker grep ss stat'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

# Ensure we can connect to docker daemon
if ! docker ps -q >/dev/null 2>&1; then
  printf "Error connecting to docker daemon (does docker ps work?)\n"
  exit 1
fi

usage () {
  cat <<EOF
  usage: ${myname} [options]

  -h           optional  Print this help message
  -l FILE      optional  Log output in FILE
  -c CHECK     optional  Comma delimited list of specific check(s)
  -e CHECK     optional  Comma delimited list of specific check(s) to exclude
  -x EXCLUDE   optional  Comma delimited list of patterns within a container name to exclude from check
EOF
}

# Get the flags
# If you add an option here, please
# remember to update usage() above.
while getopts hl:c:e:x: args
do
  case $args in
  h) usage; exit 0 ;;
  l) logger="$OPTARG" ;;
  c) check="$OPTARG" ;;
  e) checkexclude="$OPTARG" ;;
  x) exclude="$OPTARG" ;;
  *) usage; exit 1 ;;
  esac
done

if [ -z "$logger" ]; then
  logger="${myname}.log"
fi

yell_info

# Warn if not root
ID=$(id -u)
if [ "x$ID" != "x0" ]; then
  warn "Some tests might require root to run"
  sleep 3
fi

# Total Score
# Total number of test
totalChecks=0
# Warn/Note Scored 0, Pass Scored +1, Fail Scored -1
currentScore=0
# Counters of notes, warning and failed test
warnChecks=0
failChecks=0
noteChecks=0

logit "Initializing $(date)\n"
beginjson "$version" "$(date +%s)"

# Load all the tests from tests/ and run them
main () {
  # List all running containers
  if [ -z "$exclude" ]; then
    containers=$(docker ps | sed '1d' | awk '{print $NF}')
  else
    pattern=$(echo "$exclude" | sed 's/,/|/g')
    containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -Ev "$pattern" )
  fi
  # If there is a container with label docker_bench_security, memorize it:
  benchcont="nil"
  for c in $containers; do
    if docker inspect --format '{{ .Config.Labels }}' "$c" | \
     grep -e 'docker.bench.security' >/dev/null 2>&1; then
      benchcont="$c"
    fi
  done
  # List all running containers except docker-bench (use names to improve readability in logs)
  if [ -z "$exclude" ]; then
    containers=$(docker ps | sed '1d' |  awk '{print $NF}' | grep -v "$benchcont")
  else
    pattern=$(echo "$exclude" | sed 's/,/|/g')
    containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -Ev "$pattern" | grep -v "$benchcont")
  fi

  if [ -z "$containers" ]; then
    running_containers=0
  else
    running_containers=1
  fi

  for test in tests/*.sh; do
    . ./"$test"
  done

  if [ -z "$check" ] && [ ! "$checkexclude" ]; then
    cis
  elif [ -z "$check" ] && [ "$checkexclude" ]; then
    checkexcluded="$(echo "$checkexclude" | sed 's/,/|/g')"
    for c in $(grep 'check_[0-9]_' functions_lib.sh | grep -vE "$checkexcluded"); do
      "$c"
    done
  else
    for i in $(echo "$check" | sed "s/,/ /g"); do
      if command -v "$i" 2>/dev/null 1>&2; then
        "$i"
      else
        echo "Check \"$i\" doesn't seem to exist."
        continue
      fi
    done
  fi

  printf "%b\n"
  echo "${txtrst}------------------------------------------------------------------------------"
  echo "SCORE: $currentScore"
  printf "\n"

  printf "${bldgrn}Passed: $((totalChecks - failChecks - warnChecks - noteChecks))/$totalChecks  ${txtrst}-  "
  printf "${bldred}Failed: $failChecks  ${txtrst}-  "
  printf "${bldylw}Warning: $warnChecks  ${txtrst}-  "
  printf "${bldcyn}Notes: $noteChecks"

  # integerjson "checks" "$totalChecks"
  # integerjson "score" "$currentScore"

  endjson "$(date +%s)"
}

main "$@"
