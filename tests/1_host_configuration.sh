#!/bin/sh

check_1() {
  logit ""
  chkclass "1 - Host Configuration"
}

# 1.1
check_1_1() {
  check_1_1="1.1  - Ensure a separate partition for containers has been created"
  totalChecks=$((totalChecks + 1))

  if grep /var/lib/docker /etc/fstab >/dev/null 2>&1; then
    pass "$check_1_1"
    logjson "1.1" "PASS"
    currentScore=$((currentScore + 1))
  elif mountpoint -q  -- /var/lib/docker >/dev/null 2>&1; then
    pass "$check_1_1"
    logjson "1.1" "PASS"
    currentScore=$((currentScore + 1))
  else
    fail "$check_1_1"
    info "     * Mount /var/lib/docker on a dedicated partition"
    logjson "1.1" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 1.2
check_1_2() {
  check_1_2="1.2  - Ensure the container host has been Hardened"
  totalChecks=$((totalChecks + 1))
  note "$check_1_2"
  logjson "1.2" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 1.3
check_1_3() {
  check_1_3="1.3  - Ensure Docker is up to date"
  totalChecks=$((totalChecks + 1))
  docker_version=$(docker version | grep -i -A2 '^server' | grep ' Version:' \
    | awk '{print $NF; exit}' | tr -d '[:alpha:]-,')
  docker_current_version="$(date +%y.%m.0 -d @$(( $(date +%s) - 2592000)))"
  do_version_check "$docker_current_version" "$docker_version"
  if [ $? -eq 11 ]; then
    note "$check_1_3"
    info "     * Using $docker_version, verify is it up to date as deemed necessary"
    info "     * Your operating system vendor may provide support and security maintenance for Docker"
    logjson "1.3" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  else
    pass "$check_1_3"
    info "     * Using $docker_version which is current"
    info "     * Check with your operating system vendor for support and security maintenance for Docker"
    logjson "1.3" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 1.4
check_1_4() {
  check_1_4="1.4  - Ensure only trusted users are allowed to control Docker daemon"
  totalChecks=$((totalChecks + 1))
  docker_users=$(getent group docker)
  d_users=$(echo "$docker_users" | rev | cut -c 1)
  if [ "$d_users" = ":" ]; then
    pass "$check_1_4"
    logjson "1.4" "PASS"
    currentScore=$((currentScore + 1))
  else
    note "$check_1_4"
    info "     * Allowed users:"
    for u in $docker_users; do
        info "     *    $u"
    done
    logjson "1.4" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  fi
}

# 1.5
check_1_5() {
  check_1_5="1.5  - Ensure auditing is configured for the Docker daemon"
  totalChecks=$((totalChecks + 1))
  file="/usr/bin/docker "
  if command -v auditctl >/dev/null 2>&1; then
    if auditctl -l | grep "$file" >/dev/null 2>&1; then
      pass "$check_1_5"
      logjson "1.5" "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_1_5"
      info "     * No rule configured in auditctl for docker."
      info "     * Add a rule for Docker daemon."
      info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "     *      -w $file -k docker"
      info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.5" "WARN"
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
    pass "$check_1_5"
    logjson "1.5" "PASS"
    currentScore=$((currentScore + 1))
  else
    fail "$check_1_5"
    info "     * auditctl is not installed."
    info "     * Install it and add a rule for Docker daemon."
    info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
    info "     *      -w $file -k docker"
    info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
    logjson "1.5" "FAIL"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 1.6
check_1_6() {
  check_1_6="1.6  - Ensure auditing is configured for Docker files and directories - /var/lib/docker"
  totalChecks=$((totalChecks + 1))
  directory="/var/lib/docker"
  if [ -d "$directory" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $directory >/dev/null 2>&1; then
        pass "$check_1_6"
        logjson "1.6" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_6"
        info "     * No rule configured in auditctl for docker."
        info "     * Add a rule for Docker directory."
        info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "     *      -w $directory -k docker"
        info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.6" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$directory" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_6"
      logjson "1.6" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_6"
      info "     * auditctl is not installed."
      info "     * Install it and add a rule for Docker directory."
      info "     * Add a rule for Docker directory."
      info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "     *      -w $directory -k docker"
      info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.6" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_6"
    info "     * Directory not found at $directory"
    logjson "1.6" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.7
check_1_7() {
  check_1_7="1.7  - Ensure auditing is configured for Docker files and directories - /etc/docker"
  totalChecks=$((totalChecks + 1))
  directory="/etc/docker"
  if [ -d "$directory" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $directory >/dev/null 2>&1; then
        pass "$check_1_7"
        logjson "1.7" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_7"
        info "     * No rule configured in auditctl for docker."
        info "     * Add a rule for $directory directory."
        info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "     *      -w /$directory -k docker"
        info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.7" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$directory" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_7"
      logjson "1.7" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_7"
      info "     * auditctl is not installed."
      info "     * Install it and add a rule for Docker directory."
      info "     * Add a rule for $directory directory."
      info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "     *      -w $directory -k docker"
      info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.7" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_7"
    info "     * Directory not found at $directory"
    logjson "1.7" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
fi
}

# 1.8
check_1_8() {
  check_1_8="1.8  - Ensure auditing is configured for Docker files and directories - docker.service"
  totalChecks=$((totalChecks + 1))
  file="$(get_systemd_service_file docker.service)"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep "$file" >/dev/null 2>&1; then
        pass "$check_1_8"
        logjson "1.8" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_8"
        info "     * No rule configured in auditctl for docker."
        info "     * Add a rule for $file file."
        info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "     *      -w /$file -k docker"
        info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.8" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_8"
      logjson "1.8" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_8"
      info "     * auditctl is not installed."
      info "     * Install it and add a rule for Docker directory."
      info "     * Add a rule for $file directory."
      info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "     *      -w $file -k docker"
      info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.8" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_8"
    info "     * File $file not found"
    logjson "1.8" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.9
check_1_9() {
  check_1_9="1.9  - Ensure auditing is configured for Docker files and directories - docker.socket"
  totalChecks=$((totalChecks + 1))
  file="$(get_systemd_service_file docker.socket)"
  if [ -e "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep "$file" >/dev/null 2>&1; then
        pass "$check_1_9"
        logjson "1.9" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_9"
        info "    * No rule configured in auditctl for docker."
        info "    * Add a rule for $file file."
        info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "    *      -w /$file -k docker"
        info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.9" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_9"
      logjson "1.9" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_9"
      info "    * auditctl is not installed."
      info "    * Install it and add a rule for Docker directory."
      info "    * Add a rule for $file directory."
      info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "    *      -w $file -k docker"
      info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.9" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_9"
    info "     * File not found"
    logjson "1.9" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.10
check_1_10() {
  check_1_10="1.10 - Ensure auditing is configured for Docker files and directories - /etc/default/docker"
  totalChecks=$((totalChecks + 1))
  file="/etc/default/docker"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass "$check_1_10"
        logjson "1.10" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_10"
        info "    * No rule configured in auditctl for docker."
        info "    * Add a rule for $file file."
        info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "    *      -w /$file -k docker"
        info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.10" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_10"
      logjson "1.10" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_10"
      info "    * auditctl is not installed."
      info "    * Install it and add a rule for Docker directory."
      info "    * Add a rule for $file directory."
      info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "    *      -w $file -k docker"
      info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.10" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_10"
    info "     * File not found"
    logjson "1.10" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.11
check_1_11() {
  check_1_11="1.11 - Ensure auditing is configured for Docker files and directories - /etc/docker/daemon.json"
  totalChecks=$((totalChecks + 1))
  file="/etc/docker/daemon.json"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass "$check_1_11"
        logjson "1.11" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_11"
        info "    * No rule configured in auditctl for docker."
        info "    * Add a rule for $file file."
        info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "    *      -w /$file -k docker"
        info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.11" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_11"
      logjson "1.11" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_11"
      info "    * auditctl is not installed."
      info "    * Install it and add a rule for Docker directory."
      info "    * Add a rule for $file directory."
      info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "    *      -w $file -k docker"
      info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.11" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_11"
    info "     * File not found"
    logjson "1.11" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.12
check_1_12() {
  check_1_12="1.12 - Ensure auditing is configured for Docker files and directories - /usr/bin/docker-containerd"
  totalChecks=$((totalChecks + 1))
  file="/usr/bin/docker-containerd"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass "$check_1_12"
        logjson "1.12" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_12"
        info "    * No rule configured in auditctl for docker."
        info "    * Add a rule for $file file."
        info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "    *      -w /$file -k docker"
        info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.12" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_12"
      logjson "1.12" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_12"
      info "    * auditctl is not installed."
      info "    * Install it and add a rule for Docker directory."
      info "    * Add a rule for $file directory."
      info "    * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "    *      -w $file -k docker"
      info "    * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.12" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_12"
    info "     * File not found"
    logjson "1.12" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 1.13
check_1_13() {
  check_1_13="1.13 - Ensure auditing is configured for Docker files and directories - /usr/bin/docker-runc"
  totalChecks=$((totalChecks + 1))
  file="/usr/bin/docker-runc"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass "$check_1_13"
        logjson "1.13" "PASS"
        currentScore=$((currentScore + 1))
      else
        warn "$check_1_13"
        info "     * No rule configured in auditctl for docker."
        info "     * Add a rule for $file file."
        info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
        info "     *      -w /$file -k docker"
        info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
        logjson "1.13" "WARN"
        currentScore=$((currentScore + 0))
        warnChecks=$((warnChecks + 1))
      fi
    elif grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass "$check_1_13"
      logjson "1.13" "PASS"
      currentScore=$((currentScore + 1))
    else
      fail "$check_1_13"
      info "     * auditctl is not installed."
      info "     * Install it and add a rule for Docker directory."
      info "     * Add a rule for $file directory."
      info "     * For example, add the line as below line in /etc/audit/audit.rules file:"
      info "     *      -w $file -k docker"
      info "     * Then, restart the audit daemon. (e.g. service auditd restart)"
      logjson "1.13" "FAIL"
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
    fi
  else
    warn "$check_1_13"
    info "     * File not found"
    logjson "1.13" "WARN"
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}
