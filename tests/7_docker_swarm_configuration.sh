#!/bin/sh

check_7() {
  logit "\n"
  chkclass "7 - Docker Swarm Configuration"
}

# 7.1
check_7_1() {
  check_7_1="7.1  - Ensure swarm mode is not Enabled, if not needed"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:*\sinactive\s*" >/dev/null 2>&1; then
    pass "$check_7_1"
    logjson "7.1" "PASS"
    currentScore=$((currentScore + 1))
  else
    fail "$check_7_1"
    info "     * By default, a Docker engine instance will not listen on any network ports, with all communications"
    info "     * with the client coming over the Unix socket. When Docker swarm mode is enabled on a docker engine"
    info "     * instance, multiple network ports are opened on the system and made available to other systems"
    info "     * on the network for the purposes of cluster management and node communications."
    info "     * Opening network ports on a system increase its attack surface and this should be avoided unless required."
    info "     * Review the output of the 'docker info' command is 'Swarm: active' appears."
    info "     * If swarm mode has been enabled on a system in error, run:"
    info "     *        docker swarm leave"
    logjson "7.1" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 7.2
check_7_2() {
  check_7_2="7.2  - Ensure the minimum number of manager nodes have been created in a swarm"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*" >/dev/null 2>&1; then
    managernodes=$(docker node ls | grep -c "Leader")
    if [ "$managernodes" -le 1 ]; then
      pass "$check_7_2"
      logjson "7.2" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_7_2"
      info "     * Having excessive manager nodes could render the swarm more susceptible to compromise."
      info "     * If fault tolerance is not required in the manager nodes, a single node should be elected as a manager."
      info "     * If fault tolerance is required then the smallest practical odd number to achieve the appropriate"
      info "     * level of tolerance should be configured."
      info "     *    Number of managernodes: $managernodes"
      logjson "7.2" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    pass "$check_7_2 (Swarm mode not enabled)"
    logjson "7.2" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.3
check_7_3() {
  check_7_3="7.3  - Ensure swarm services are binded to a specific host interface"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*" >/dev/null 2>&1; then
    ss -lnt | grep -e '\[::]:2377 ' -e ':::2377' -e '*:2377 ' -e ' 0\.0\.0\.0:2377 ' >/dev/null 2>&1
    if [ $? -eq 1 ]; then
      pass "$check_7_3"
      logjson "7.3" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_7_3"
      info "     * The default value for the --listen-addr flag is 0.0.0.0:2377 which means that the swarm services will"
      info "     * listen on all interfaces on the host. If a host has multiple network interfaces this may be undesirable"
      info "     * as it may expose the docker swarm services to networks which are not involved in the operation"
      info "     * of the swarm."
      info "     * By passing a specific IP address to the '--listen-addr', a specific network interface can be specified"
      info "     * limiting this exposure."
      logjson "7.3" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    pass "$check_7_3 (Swarm mode not enabled)"
    logjson "7.3" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.4
check_7_4(){
  check_7_4="7.4  - Ensure data exchanged between containers are encrypted on different nodes on the overlay network"
  totalChecks=$((totalChecks + 1))
  if docker network ls --filter driver=overlay --quiet | \
    xargs docker network inspect --format '{{.Name}} {{ .Options }}' 2>/dev/null | \
      grep -v 'encrypted:' 2>/dev/null 1>&2; then
    fail "$check_7_4"
    info "     * By default, data exchanged between containers on different nodes on the overlay network"
    info "     * are not encrypted in the Docker swarm mode."
    info "     * Create overlay network with '--opt encrypted' flag."
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
    for encnet in $(docker network ls --filter driver=overlay --quiet); do
      if docker network inspect --format '{{.Name}} {{ .Options }}' "$encnet" | \
        grep -v 'encrypted:' 2>/dev/null 1>&2; then
        info "     * Unencrypted overlay network: $(docker network inspect --format '{{ .Name }} ({{ .Scope }})' "$encnet")"
        logjson "7.4" "FAIL: $(docker network inspect --format '{{ .Name }} ({{ .Scope }})' "$encnet")"
      fi
    done
  else
    pass "$check_7_4"
    logjson "7.4" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.5
check_7_5() {
  check_7_5="7.5  - Ensure Docker's secret management commands are used for managing secrets in a Swarm cluster"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    if [ "$(docker secret ls -q | wc -l)" -ge 1 ]; then
      pass "$check_7_5"
      logjson "7.5" "PASS"
      currentScore=$((currentScore + 1))
    else
      note "$check_7_5"
      info "     * Follow 'docker secret' documentation and use it to manage secrets effectively."
      info "     * Ref.:    https://docs.docker.com/engine/reference/commandline/secret/"
      logjson "7.5" "NOTE"
      currentScore=$((currentScore + 0))
      noteChecks=$((noteChecks + 1))
    fi
  else
    pass "$check_7_5 (Swarm mode not enabled)"
    logjson "7.5" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.6
check_7_6() {
  check_7_6="7.6  - Ensure swarm manager is run in auto-lock mode"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    if ! docker swarm unlock-key 2>/dev/null | grep 'SWMKEY' 2>/dev/null 1>&2; then
      fail "$check_7_6"
      info "     * When Docker restarts, both the TLS key used to encrypt communication among swarm nodes, "
      info "     * and the key used to encrypt and decrypt Raft logs on disk, are loaded into each manager node's memory."
      info "     * You should protect the mutual TLS encryption key and the key used to encrypt and decrypt Raft logs"
      info "     * at rest. This protection could be enabled by initializing swarm with '--autolock' flag."
      info "     * If you are initializing swarm, use the below command:"
      info "     *        docker swarm init --autolock"
      info "     * If you want to set --autolock on an existing swarm manager node, use the below command:"
      info "              docker swarm update --autolock"
      info "     * Beware that a swarm in auto-lock mode won't recover from a restart without manual intervention"
      info "       to unlock the key (availability problem)"
      logjson "7.6" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    else
      pass "$check_7_6"
      logjson "7.6" "PASS"
      currentScore=$((currentScore + 1))
    fi
  else
    pass "$check_7_6 (Swarm mode not enabled)"
    logjson "7.6" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.7
check_7_7() {
  check_7_7="7.7  - Ensure swarm manager auto-lock key is rotated periodically"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    warn "$check_7_7"
    info "     * Swarm manager auto-lock key is not automatically rotated. You should rotate them periodically"
    info "     * as a best practice:"
    info "     *        docker swarm unlock-key --rotate"
    logjson "7.7" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_7_7 (Swarm mode not enabled)"
    logjson "7.7" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.8
check_7_8() {
  check_7_8="7.8  - Ensure node certificates are rotated as appropriate"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    if docker info 2>/dev/null | grep "Expiry Duration: 2 days"; then
      pass "$check_7_8"
      logjson "7.8" "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_7_8"
      info "     * Certificate rotation ensures that in an event such as compromised node or key, it is difficult"
      info "     * to impersonate a node. By default, node certificates are rotated every 90 days. "
      info "     * You should rotate it more often or as appropriate in your environment."
      info "     * e.g.:    docker swarm update --cert-expiry 48h"
      logjson "7.8" "WARN"
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  else
    pass "$check_7_8 (Swarm mode not enabled)"
    logjson "7.8" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.9
check_7_9() {
  check_7_9="7.9  - Ensure CA certificates are rotated as appropriate"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    warn "$check_7_9"
    info "     * Node certificates depend upon root CA certificates. For operational security, it is important to rotate"
    info "     * these frequently. Currently, root CA certificates are not rotated automatically."
    info "     * You should thus establish a process to rotate it at the desired frequency:"
    info "     *         docker swarm ca --rotate"
    logjson "7.9" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  else
    pass "$check_7_9 (Swarm mode not enabled)"
    logjson "7.9" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 7.10
check_7_10() {
  check_7_10="7.10 - Ensure management plane traffic has been separated from data plane traffic"
  totalChecks=$((totalChecks + 1))
  if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    note "$check_7_10"
    info "     * Separating the management plane traffic from data plane traffic ensures that these traffics are on their"
    info "     * respective paths. These paths could then be individually monitored and could be tied to different traffic"
    info "     * control policies and monitoring. It also ensures that management plane is always reachable despite"
    info "     * the huge volume of data flow."
    info "     * Initialize Swarm with dedicated interfaces for management and data planes respectively:"
    info "     * (but require 2 network interface cards per node)"
    info "     * e.g.:    docker swarm init --advertise-addr=192.168.0.1 --data-path-addr=17.1.0.3"
    logjson "7.10" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  else
    pass "$check_7_10 (Swarm mode not enabled)"
    logjson "7.10" "PASS"
    currentScore=$((currentScore + 1))
  fi
}
