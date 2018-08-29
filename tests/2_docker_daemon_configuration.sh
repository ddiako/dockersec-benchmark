#!/bin/sh

check_2() {
  logit "\n"
  chkclass "2 - Docker daemon configuration"
}

# 2.1
check_2_1() {
  check_2_1="2.1  - Ensure network traffic is restricted between containers on the default bridge"
  totalChecks=$((totalChecks + 1))
  if get_docker_effective_command_line_args '--icc' | grep false >/dev/null 2>&1; then
    pass "$check_2_1"
    logjson "2.1" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_configuration_file_args 'icc' | grep "false" >/dev/null 2>&1; then
    pass "$check_2_1"
    logjson "2.1" "PASS"
    currentScore=$((currentScore + 1))
  else
    fail "$check_2_1"
    info "     * Run the docker in daemon mode and pass '--icc=false' as argument."
    info "     * The inter container communication would be disabled."
    info "     * e.g.:      /usr/bin/dockerd --icc=false"
    logjson "2.1" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 2.2
check_2_2() {
  check_2_2="2.2  - Ensure the logging level is set to 'info'"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'log-level' >/dev/null 2>&1; then
    if get_docker_configuration_file_args 'log-level' | grep info >/dev/null 2>&1; then
      pass "$check_2_2"
      logjson "2.2" "PASS"
      currentScore=$((currentScore + 1))
    elif [ -z "$(get_docker_configuration_file_args 'log-level')" ]; then
      pass "$check_2_2"
      logjson "2.2" "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_2_2"
      info "     * Until and unless required, you should not run Docker daemon at 'debug' log level."
      info "     * Run the Docker daemon as below: "
      info "     *        dockerd --log-level='info'"
      logjson "2.2" "WARN"
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  elif get_docker_effective_command_line_args '-l'; then
    if get_docker_effective_command_line_args '-l' | grep "info" >/dev/null 2>&1; then
      pass "$check_2_2"
      logjson "2.2" "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_2_2"
      info "     * Until and unless required, you should not run Docker daemon at 'debug' log level."
      info "     *        dockerd --log-level='info'"
      logjson "2.2" "WARN"
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  else
    pass "$check_2_2"
    logjson "2.2" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.3
check_2_3() {
  check_2_3="2.3  - Ensure Docker is allowed to make changes to iptables"
  totalChecks=$((totalChecks + 1))
  if get_docker_effective_command_line_args '--iptables' | grep "false" >/dev/null 2>&1; then
    warn "$check_2_3"
    info "     * Docker is not able to modify iptable if running with '--iptables=false.'"
    logjson "2.3" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  elif get_docker_configuration_file_args 'iptables' | grep "false" >/dev/null 2>&1; then
    warn "$check_2_3"
    info "     * Docker is not able to modify iptable if running with '--iptables=false.'"
    logjson "2.3" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_2_3"
    logjson "2.3" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.4
check_2_4() {
  check_2_4="2.4  - Ensure insecure registries are not used"
  totalChecks=$((totalChecks + 1))
  if get_docker_effective_command_line_args '--insecure-registry' | grep "insecure-registry" >/dev/null 2>&1; then
    warn "$check_2_4"
    info "     * Docker is accepting registry without TLS or with unvalid certificate."
    info "     * You should avoid running Docker with --insecure-registry as argument or as config option."
    logjson "2.4" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  elif ! [ -z "$(get_docker_configuration_file_args 'insecure-registries')" ]; then
    if get_docker_configuration_file_args 'insecure-registries' | grep '\[]' >/dev/null 2>&1; then
      pass "$check_2_4"
      logjson "2.4" "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_2_4"
      info "     * Docker is accepting registry without TLS or with unvalid certificate."
      info "     * You should avoid running Docker with --insecure-registry as argument or as config option."
      logjson "2.4" "WARN"
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  else
    pass "$check_2_4"
    logjson "2.4" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.5
check_2_5() {
  check_2_5="2.5  - Ensure aufs storage driver is not used"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "^Storage Driver:\s*aufs\s*$" >/dev/null 2>&1; then
    warn "$check_2_5"
    info "     * You shouldn't use deprecated storage driver."
    logjson "2.5" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_2_5"
    logjson "2.5" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.6
check_2_6() {
  check_2_6="2.6  - Ensure TLS authentication for Docker daemon is configured"
  totalChecks=$((totalChecks + 1))
  if grep -i 'tcp://' "$CONFIG_FILE" 2>/dev/null 1>&2; then
    if [ $(get_docker_configuration_file_args '"tls":' | grep 'true') ] || \
      [ $(get_docker_configuration_file_args '"tlsverify' | grep 'true') ] ; then
      if get_docker_configuration_file_args 'tlskey' | grep -v '""' >/dev/null 2>&1; then
        if get_docker_configuration_file_args 'tlsverify' | grep 'true' >/dev/null 2>&1; then
          pass "$check_2_6"
          logjson "2.6" "PASS"
          currentScore=$((currentScore + 1))
        else
          warn "$check_2_6"
          info "     * Docker daemon currently listening on TCP with TLS, but without verification of the certificate."
          info "     * To test it, run:"
          info "     *        ps -ef | grep dockerd"
          info "     * Ensure that the following parameters are present: --tlsverify --tlscacert --tlscert --tlskey"
          logjson "2.6" "WARN"
          currentScore=$((currentScore - 0))
          warnChecks=$((warnChecks + 1))
        fi
      fi
    else
      warn "$check_2_6"
      info "     * Docker daemon currently listening on TCP without TLS"
      logjson "2.6" "WARN"
      currentScore=$((currentScore - 0))
      warnChecks=$((warnChecks + 1))
    fi
  elif get_docker_cumulative_command_line_args '-H' | grep -vE '(unix|fd)://' >/dev/null 2>&1; then
    if get_docker_cumulative_command_line_args '--tlskey' | grep 'tlskey=' >/dev/null 2>&1; then
      if get_docker_cumulative_command_line_args '--tlsverify' | grep 'tlsverify' >/dev/null 2>&1; then
        pass "$check_2_6"
        logjson "2.6" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_2_6"
        info "     * Docker daemon currently listening on TCP with TLS, but without verification of the certificate."
        info "     * To test it, run:"
        info "     *        ps -ef | grep dockerd"
        info "     * Ensure that the following parameters are present: --tlsverify --tlscacert --tlscert --tlskey"
        logjson "2.6" "WARN"
        currentScore=$((currentScore - 0))
        warnChecks=$((warnChecks + 1))
      fi
    else
      warn "$check_2_6"
      info "     * Docker daemon currently listening on TCP without TLS"
      logjson "2.6" "WARN"
      currentScore=$((currentScore - 0))
      warnChecks=$((warnChecks + 1))
    fi
  else
    note "$check_2_6"
    info "     * Docker daemon not listening on TCP"
    logjson "2.6" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  fi
}

# 2.7
check_2_7() {
  check_2_7="2.7  - Ensure the default ulimit is configured appropriately"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'default-ulimit' | grep -v '{}' >/dev/null 2>&1; then
    pass "$check_2_7"
    logjson "2.7" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_effective_command_line_args '--default-ulimit' | grep "default-ulimit" >/dev/null 2>&1; then
    pass "$check_2_7"
    logjson "2.7" "PASS"
    currentScore=$((currentScore + 1))
  else
    note "$check_2_7"
    info "     * Default ulimit doesn't appear to be set"
    logjson "2.7" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  fi
}

# 2.8
check_2_8() {
  check_2_8="2.8  - Enable user namespace support"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'userns-remap' | grep -v '""'; then
    pass "$check_2_8"
    logjson "2.8" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_effective_command_line_args '--userns-remap' | grep "userns-remap" >/dev/null 2>&1; then
    pass "$check_2_8"
    logjson "2.8" "PASS"
    currentScore=$((currentScore + 1))
  else
    warn "$check_2_8"
    info "     * User namespace support is not enabled in Docker daemon."
    info "     * Can be ignored if the container images have a pre-defined"
    info "     * non-root user."
    info "     * To enable: /usr/bin/dockerd --userns-remap=default"
    info "     * Read the documentation before enabling it."
    info "     *    - http://man7.org/linux/man-pages/man7/user_namespaces.7.html"
    info "     *    - https://docs.docker.com/engine/reference/commandline/daemon/"
    info "     *    - https://github.com/docker/docker/issues/21050"
    info "     *    - http://events.linuxfoundation.org/sites/events/files/slides/"
    info "     *        User%20Namespaces%20-%20ContainerCon%202015%20-%2016-9-final_0.pdf"
    logjson "2.8" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 2.9
check_2_9() {
  check_2_9="2.9  - Ensure the default cgroup usage has been confirmed"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'cgroup-parent' | grep -v '""'; then
    warn "$check_2_9"
    info "     * Confirm cgroup usage."
    info "     * To test:   ps -ef | grep dockerd"
    info "     *   Ensure that the '--cgroup-parent' parameter is either not set"
    info "     *   or is set as appropriate non-default cgroup."
    logjson "2.9" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  elif get_docker_effective_command_line_args '--cgroup-parent' | grep "cgroup-parent" >/dev/null 2>&1; then
    warn "$check_2_9"
    info "     * Confirm cgroup usage"
    info "     * To test:   ps -ef | grep dockerd"
    info "     *   Ensure that the '--cgroup-parent' parameter is either not set"
    info "     *   or is set as appropriate non-default cgroup."
    logjson "2.9" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_2_9"
    logjson "2.9" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.10
check_2_10() {
  check_2_10="2.10 - Ensure base device size is not changed until needed"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'storage-opts' | grep "dm.basesize" >/dev/null 2>&1; then
    warn "$check_2_10"
    info "     * In certain circumstances, you might need containers bigger than the default 10G in size."
    info "     * In these cases, carefully choose the base device size."
    info "     * To test:   ps -ef | grep dockerd"
    info "     *   Execute the above command and it should not show any --storage-opt dm.basesize parameters."
    logjson "2.10" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  elif get_docker_effective_command_line_args '--storage-opt' | grep "dm.basesize" >/dev/null 2>&1; then
    warn "$check_2_10"
    info "     * In certain circumstances, you might need containers bigger than the default 10G in size."
    info "     * In these cases, carefully choose the base device size."
    info "     * To test:   ps -ef | grep dockerd"
    info "     *   Execute the above command and it should not show any --storage-opt dm.basesize parameters."
    logjson "2.10" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_2_10"
    logjson "2.10" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.11
check_2_11() {
  check_2_11="2.11 - Ensure that authorization for Docker client commands is enabled"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'authorization-plugins' | grep -v '\[]'; then
    pass "$check_2_11"
    logjson "2.11" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_effective_command_line_args '--authorization-plugin' | grep "authorization-plugin" >/dev/null 2>&1; then
    pass "$check_2_11"
    logjson "2.11" "PASS"
    currentScore=$((currentScore + 1))
  else
    fail "$check_2_11"
    info "     * There are no granular access policies configred for managing access to Docker daemon."
    info "     * Granular access can be configured using an authorization-plugin:"
    info "     * e.g.     dockerd --authorization-plugin=<PLUGIN_ID>"
    info "     * You can consider using authz plugin:"
    info "     * Ref.     https://github.com/twistlock/authz"
    logjson "2.11" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 2.12
check_2_12() {
  check_2_12="2.12 - Ensure centralized and remote logging is configured"
  totalChecks=$((totalChecks + 1))
  if docker info --format '{{ .LoggingDriver }}' | grep 'json-file' >/dev/null 2>&1; then
    fail "$check_2_12"
    info "     * No centralized logs configured."
    info "     * Start the docker daemon with a logging driver."
    info "     * e.g.     dockerd --log-driver=syslog --log-opt syslog-address=tcp://192.xxx.xxx.xxx"
    logjson "2.12" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  else
    pass "$check_2_12"
    logjson "2.12" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 2.13
check_2_13() {
  docker_version=$(docker version | grep -i -A2 '^server' | grep ' Version:' \
    | awk '{print $NF; exit}' | tr -d '[:alpha:]-,.')
  totalChecks=$((totalChecks + 1))
  if [ "$docker_version" -lt 1712 ]; then
    check_2_13="2.13 - Ensure operations on legacy registry (v1) are Disabled"
    if get_docker_configuration_file_args 'disable-legacy-registry' | grep 'true' >/dev/null 2>&1; then
      pass "$check_2_13"
      logjson "2.13" "PASS"
      currentScore=$((currentScore + 1))
    elif get_docker_effective_command_line_args '--disable-legacy-registry' | grep "disable-legacy-registry" >/dev/null 2>&1; then
      pass "$check_2_13"
      logjson "2.13" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_2_13"
      info "     * Operations on Docker legacy registry should be restricted."
      info "     * Start the docker daemon as below to disable the old registry v1:"
      info "     *        dockerd --disable-legacy-registry"
      logjson "2.13" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    check_2_13="2.13 - Ensure operations on legacy registry (v1) are Disabled (Deprecated)"
    warn "$check_2_13"
    info "     * Your Docker instance doesn't support registry v2."
    logjson "2.13" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 2.14
check_2_14() {
  check_2_14="2.14 - Ensure live restore is Enabled"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Live Restore Enabled:\s*true\s*" >/dev/null 2>&1; then
    pass "$check_2_14"
    logjson "2.14" "PASS"
    currentScore=$((currentScore + 1))
  else
    if docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*" >/dev/null 2>&1; then
      pass "$check_2_14 (Incompatible with swarm mode)"
      logjson "2.14" "PASS"
      currentScore=$((currentScore + 1))
    elif get_docker_effective_command_line_args '--live-restore' | grep "live-restore" >/dev/null 2>&1; then
      pass "$check_2_14"
      logjson "2.14" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_2_14"
      info "     * Live restore is not enabled."
      info "     * Setting '--live-restore' flag in the docker daemon ensures that container execution"
      info "     * is not interrupted when the docker daemon is not available."
      info "     * Run the docker in daemon mode and pass '--live-restore' as an argument:"
      info "     * e.g.       dockerd --live-restore"
      logjson "2.14" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  fi
}

# 2.15
check_2_15() {
  check_2_15="2.15 - Ensure Userland Proxy is Disabled"
  totalChecks=$((totalChecks + 1))
  if get_docker_configuration_file_args 'userland-proxy' | grep false >/dev/null 2>&1; then
    pass "$check_2_15"
    logjson "2.15" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_effective_command_line_args '--userland-proxy=false' 2>/dev/null | grep "userland-proxy=false" >/dev/null 2>&1; then
    pass "$check_2_15"
    logjson "2.15" "PASS"
    currentScore=$((currentScore + 1))
  else
    warn "$check_2_15"
    logjson "2.15" "WARN"
    info "     * Where hairpin NAT is available, the userland proxy should be disabled on startup to reduce"
    info "     * the attack surface of the installation."
    info "     * e.g.       dockerd --userland-proxy=false"
    info "     * (Some systems with older Linux kernels may not be able to support hairpin NAT)"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 2.16
check_2_16() {
  check_2_16="2.16 - Ensure daemon-wide custom seccomp profile is applied, if needed"
  totalChecks=$((totalChecks + 1))
  if docker info --format '{{ .SecurityOptions }}' | grep 'name=seccomp,profile=default' 2>/dev/null 1>&2; then
    pass "$check_2_16"
    logjson "2.16" "PASS"
    currentScore=$((currentScore + 1))
  else
    warning "$check_2_16"
    info "     * Docker isn't running with a limited number of systemcalls activated."
    info "     * You can override the default seccomp profile with:"
    info "     *          dockerd --seccomp-profile </path/to/seccomp/profile>"
    info "     * Good to restrict the attack surface from a security point of view, but misconfigured"
    info "     * , could possibly interrupt your container environment."
    info "     * For more info:"
    info "     *          https://docs.docker.com/engine/security/seccomp/"
    logjson "2.16" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 2.17
check_2_17() {
  check_2_17="2.17 - Ensure experimental features are avoided in production"
  totalChecks=$((totalChecks + 1))
  if docker version -f '{{.Server.Experimental}}' | grep false 2>/dev/null 1>&2; then
    pass "$check_2_17"
    logjson "2.17" "PASS"
    currentScore=$((currentScore + 1))
  else
    warn "$check_2_17"
    info "     * Do not pass '--experimental' as a runtime parameter to the docker daemon."
    logjson "2.17" "WARN"
    currentScore=$((currentScore - 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 2.18
check_2_18() {
  check_2_18="2.18 - Ensure containers are restricted from acquiring new privileges"
  totalChecks=$((totalChecks + 1))
  if get_docker_effective_command_line_args '--no-new-privileges' | grep "no-new-privileges" >/dev/null 2>&1; then
    pass "$check_2_18"
    logjson "2.18" "PASS"
    currentScore=$((currentScore + 1))
  elif get_docker_configuration_file_args 'no-new-privileges' | grep true >/dev/null 2>&1; then
    pass "$check_2_18"
    logjson "2.18" "PASS"
    currentScore=$((currentScore + 1))
  else
    warn "$check_2_18"
    info "     * Setting the 'no_new_priv' bit at the daemon level ensures that by default all new containers"
    info "     * are restricted from acquiring new privileges."
    info "     * Beware that 'no_new_priv' prevents LSMs like SELinux from transitioning to process labels"
    info "     * that have access not allowed to the current process."
    info "     * To activate the 'no_new_priv' bit for the docker daemon, run docker with:"
    info "     *          dockerd --no-new-privileges"
    logjson "2.18" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}
