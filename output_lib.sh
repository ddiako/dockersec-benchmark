#!/bin/sh
#ROWS=(
#    '   '
    # dim / bright
#    ' 30' ' 90' # black / dark gray
#    ' 31' ' 91' # red
#    ' 32' ' 92' # green
#    ' 33' ' 93' # yellow
#    ' 34' ' 94' # blue
#    ' 35' ' 95' # purple
#    ' 36' ' 96' # cyan
#    ' 37' ' 97' # light gray / white
#)
bldred='\033[1;31m' # Red
bldgrn='\033[1;32m' # Green
bldylw='\033[1;33m' # Yellow
bldblu='\033[1;34m' # Blue
bldppl='\033[1;35m' # Purple
bldcyn='\033[1;36m' # Cyan
bldlgr='\033[1;37m' # Light gray
txtrst='\033[0m'

header () {
printf "%b\n" "${bldgrn}# --------------------------------------------------------------------------------------------------------"
printf "%b\n" "${bldgrn}# - Dockersec Benchmark for Security Enhanced"
printf "%b\n" "${bldgrn}# - by @ddiako (https://github.com/ddiako/dockersec-benchmark)"
printf "%b\n" "${bldgrn}# - --- VERSION: $1 ---"
printf "%b\n" "${bldgrn}# -"
printf "%b\n" "${bldgrn}# - Checks for dozens of common best-practices around deploying Docker containers in production."
printf "%b\n" "${bldgrn}# -"
printf "%b\n" "${bldgrn}# - Inspired by docker-bench-security (https://github.com/docker/docker-bench-security)"
printf "%b\n" "${bldgrn}# - Benchmark inspired by the [CIS Docker Community Edition Benchmark v1.1.0]"
printf "%b\n" "${bldgrn}# - (https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_Community_Edition_Benchmark_v1.1.0.pdf)"
printf "%b\n" "${bldgrn}# --------------------------------------------------------------------------------------------------------"
}

logit () {
  printf "%b\n" "$1" | tee -a "$logger"
}

chkclass () {
  printf "%b\n" "${bldblu} $1" | tee -a "$logger"
}

info () {
  printf "%b\n" "      ${txtrst} $1" | tee -a "$logger"
}

pass () {
  printf "%b\n" "${bldgrn}[PASS] $1" | tee -a "$logger"
}

warn () {
  printf "%b\n" "${bldylw}[WARN] $1" | tee -a "$logger"
}

fail () {
  printf "%b\n" "${bldred}[FAIL] $1" | tee -a "$logger"
}

note () {
  printf "%b\n" "${bldcyn}[NOTE] $1" | tee -a "$logger"
}

yell () {
  printf "%b\n" "${bldppl}$1${txtrst}\n"
}

beginjson () {
  printf "{\n  \"dockerbenchsecurity\": \"%s\",\n  \"start\": %s," "$1" "$2" | tee "$logger.json" 2>/dev/null 1>&2
}

endjson (){
  printf "\n  \"end\": %s \n}\n" "$1" | tee -a "$logger.json" 2>/dev/null 1>&2
}

logjson (){
  printf "\n  \"%s\": \"%s\"," "$1" "$2" | tee -a "$logger.json" 2>/dev/null 1>&2
}

integerjson (){
  printf "\n  \"%s\": %s," "$1" "$2" | tee -a "$logger.json" 2>/dev/null 1>&2
}
