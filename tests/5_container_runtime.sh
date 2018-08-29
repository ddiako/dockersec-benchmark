#!/bin/sh

check_5() {
logit "\n"
chkclass "5  - Container Runtime"
}

check_running_containers() {
  # If containers is empty, there are no running containers
  if [ -z "$containers" ]; then
    info "     * No containers running, skipping Section 5"
    running_containers=0
  else
    running_containers=1
    # Make the loop separator be a new-line in POSIX compliant fashion
    set -f; IFS=$'
  '
  fi
}

# 5.1
check_5_1() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_1="5.1  - Ensure AppArmor Profile is Enabled"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    policy=$(docker inspect --format 'AppArmorProfile={{ .AppArmorProfile }}' "$c")

    if [ "$policy" = "AppArmorProfile=" -o "$policy" = "AppArmorProfile=[]" -o "$policy" = "AppArmorProfile=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_1"
        info "     * If AppArmor is applicable for your Linux OS, use it. You may have to follow below set of steps:"
        info "     *    1. Verify if AppArmor is installed. If not, install it."
        info "     *    2. Create or import a AppArmor profile for Docker containers."
        info "     *    3. Put this profile in enforcing mode."
        info "     *    4. Start your Docker container using the customized AppArmor profile."
        info "     *    e.g.     docker run --interactive --tty --security-opt='apparmor:PROFILENAME' centos /bin/bash"
        info "     * No AppArmorProfile Found for: $c"
        logjson "5.1" "FAIL: $c"
        fail=1
      else
        info "     * No AppArmorProfile Found for: $c"
        logjson "5.1" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none without AppArmor
  if [ $fail -eq 0 ]; then
      pass "$check_5_1"
      logjson "5.1" "PASS"
      # If AppArmor is activated, The SELinux test will fail, so the score is incremented by 2
      currentScore=$((currentScore + 2))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failchecks + 1))
  fi
}

# 5.2
check_5_2() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_2="5.2  - Ensure SELinux security options are set, if applicable"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    policy=$(docker inspect --format 'SecurityOpt={{ .HostConfig.SecurityOpt }}' "$c")

    if [ "$policy" = "SecurityOpt=" -o "$policy" = "SecurityOpt=[]" -o "$policy" = "SecurityOpt=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_2"
        info "     * If SELinux is applicable for your Linux OS, use it. You may have to follow below set of steps:"
        info "     *    1. Set the SELinux State."
        info "     *    2. Set the SELinux Policy."
        info "     *    3. Create or import a SELinux policy template for Docker containers."
        info "     *    4. Start Docker in daemon mode with SELinux enabled."
        info "     *    e.g.     docker daemon --selinux-enabled"
        info "     *    5. Start your Docker container using the security options."
        info "     *    e.g.     docker run --interactive --tty --security-opt label=level:TopSecret centos /bin/bash"
        info "     * No SecurityOptions Found: $c"
        logjson "5.2" "FAIL: $c"
        fail=1
      else
        info "     * No SecurityOptions Found: $c"
        logjson "5.2" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none without SELinux
  if [ $fail -eq 0 ]; then
      pass "$check_5_2"
      logjson "5.2" "PASS"
      # If SELinux is activated, The AppArmor test will fail, so the score is incremented by 2
      currentScore=$((currentScore + 2))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.3
check_5_3() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_3="5.3  - Ensure Linux Kernel Capabilities are restricted within containers"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    container_caps=$(docker inspect --format 'CapAdd={{ .HostConfig.CapAdd}}' "$c")
    caps=$(echo "$container_caps" | tr "[:lower:]" "[:upper:]" | \
      sed 's/CAPADD/CapAdd/' | \
      sed -r "s/AUDIT_WRITE|CHOWN|DAC_OVERRIDE|FOWNER|FSETID|KILL|MKNOD|NET_BIND_SERVICE|NET_RAW|SETFCAP|SETGID|SETPCAP|SETUID|SYS_CHROOT|\s//g")

    if [ "$caps" != 'CapAdd=' -a "$caps" != 'CapAdd=[]' -a "$caps" != 'CapAdd=<no value>' -a "$caps" != 'CapAdd=<nil>' ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn "$check_5_3"
        info "     * Docker supports the addition and removal of capabilities, allowing the use of a non-default profile."
        info "     * This may make Docker more secure through capability removal, or less secure through the addition of"
        info "     * capabilities. It is thus recommended to remove all capabilities except those explicitly required for"
        info "     * your container process."
        info "     * Verify that the added and dropped Linux Kernel Capabilities are in line with the ones needed"
        info "     * for container process for each container instance."
        info "     * By default, below capabilities are available for containers: "
        info "     *      AUDIT_WRITE CHOWN DAC_OVERRIDE FOWNER FSETID KILL MKNOD NET_BIND_SERVICE NET_RAW"
        info "     *      SETFCAP SETGID SETPCAP SETUID SYS_CHROOT"
        info "     * Capabilities added:    $caps to $c"
        logjson "5.3" "WARN: $c"
        fail=1
      else
        info "     * Capabilities added:    $caps to $c"
        logjson "5.3" "WARN: $c"
      fi
    fi
  done
  # We went through all the containers and found none with extra capabilities
  if [ $fail -eq 0 ]; then
      pass "$check_5_3"
      logjson "5.3" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 0))
      warnChecks=$((warnChecks + 1))
  fi
}

# 5.4
check_5_4() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_4="5.4  - Ensure privileged containers are not used"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    privileged=$(docker inspect --format '{{ .HostConfig.Privileged }}' "$c")

    if [ "$privileged" = "true" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_4"
        info "     * The '--privileged' flag gives all capabilities to the container, and it also lifts all"
        info "     * the limitations enforced by the device cgroup controller. In other words, the container can then"
        info "     * do almost everything that the host can do. This flag exists to allow special use-cases,"
        info "     * like running Docker within Docker."
        info "     * You should avoid running the container with the '--privileged' flag."
        info "     * Container running in Privileged mode: $c"
        logjson "5.4" "FAIL: $c"
        fail=1
      else
        info "     * Container running in Privileged mode: $c"
        logjson "5.4" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found no privileged containers
  if [ $fail -eq 0 ]; then
      pass "$check_5_4"
      logjson "5.4" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.5
check_5_5() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_5="5.5  - Ensure sensitive host system directories are not mounted on containers"
  totalChecks=$((totalChecks + 1))

  # List of sensitive directories to test for. Script uses new-lines as a separator.
  # Note the lack of identation. It needs it for the substring comparison.
  sensitive_dirs='/
/boot
/dev
/etc
/lib
/proc
/sys
/usr'
  fail=0
  for c in $containers; do
    if docker inspect --format '{{ .VolumesRW }}' "$c" 2>/dev/null 1>&2; then
      volumes=$(docker inspect --format '{{ .VolumesRW }}' "$c")
    else
      volumes=$(docker inspect --format '{{ .Mounts }}' "$c")
    fi
    # Go over each directory in sensitive dir and see if they exist in the volumes
    for v in $sensitive_dirs; do
      sensitive=0
      if echo "$volumes" | grep -e "{.*\s$v\s.*true\s}" 2>/tmp/null 1>&2; then
        sensitive=1
      fi
      if [ $sensitive -eq 1 ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          fail "$check_5_5"
          info "     * If sensitive directories are mounted in read-write mode, it would be possible to make changes"
          info "     * to files within those sensitive directories which could bring down security implications"
          info "     * or unwarranted changes that could put the Docker host in compromised state."
          info "     * Avoid mounting host sensitive directories on containers, especially in read-write mode."
          info "     * Sensitive directory $v mounted in: $c"
          logjson "5.5" "FAIL: $v in $c"
          fail=1
        else
          info "     * Sensitive directory $v mounted in: $c"
          logjson "5.5" "FAIL: $v in $c"
        fi
      fi
    done
  done
  # We went through all the containers and found none with sensitive mounts
  if [ $fail -eq 0 ]; then
      pass "$check_5_5"
      logjson "5.5" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.6
check_5_6() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_6="5.6  - Ensure ssh is not run within containers"
  totalChecks=$((totalChecks + 1))

  fail=0
  printcheck=0
  for c in $containers; do

    processes=$(docker exec "$c" ps -el 2>/dev/null | grep -c sshd | awk '{print $1}')
    if [ "$processes" -ge 1 ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn "$check_5_6"
        info "     * SSH server should not be running within the container."
        info "     * You should uninstall SSH server from the container and use nsenteror any other commands"
        info "     * such as 'docker exec' or 'docker attach' to interact with the container instance. "
        info "     * e.g.:     docker exec --interactive --tty $INSTANCE_ID sh"
        info "     * Or        docker attach $INSTANCE_ID"
        info "     * Container running sshd: $c"
        logjson "5.6" "WARN: $c"
        fail=1
        printcheck=1
      else
        info "     * Container running sshd: $c"
        logjson "5.6" "WARN: $c"
      fi
    fi

    exec_check=$(docker exec "$c" ps -el 2>/dev/null)
    if [ $? -eq 255 ]; then
        if [ $printcheck -eq 0 ]; then
          warn "$check_5_6"
          logjson "5.6" "WARN"
          printcheck=1
        fi
      warn "     * Docker exec fails: $c"
      logjson "5.6" "WARN: $c"
      fail=1
    fi

  done
  # We went through all the containers and found none with sshd
  if [ $fail -eq 0 ]; then
      pass "$check_5_6"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 0))
      warnChecks=$((warnChecks + 1))
  fi
}

# 5.7
check_5_7() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_7="5.7  - Ensure privileged ports are not mapped within containers"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    # Port format is private port -> ip: public port
    ports=$(docker port "$c" | awk '{print $0}' | cut -d ':' -f2)

    # iterate through port range (line delimited)
    for port in $ports; do
    if [ ! -z "$port" ] && [ "$port" -lt 1024 ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          fail "$check_5_7"
          info "     * The TCP/IP port numbers below 1024 shouldn't be used."
          info "     * Privileged Port in use:     $port in $c"
          logjson "5.7" "FAIL: $port in $c"
          fail=1
        else
          info "     * Privileged Port in use:     $port in $c"
          logjson "5.7" "FAIL: $port in $c"
        fi
      fi
    done
  done
  # We went through all the containers and found no privileged ports
  if [ $fail -eq 0 ]; then
      pass "$check_5_7"
      logjson "5.7" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.8
check_5_8() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_8="5.8  - Ensure only needed ports are open on the container"
  totalChecks=$((totalChecks + 1))
  note "$check_5_8"
  info "     * Review the list and ensure that the ports mapped are the ones that are really needed for the container:"
  info "     *        docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'"
  info "     * Fix the Dockerfile of the container image to expose only needed ports by your containerized application."
  info "     * You can also completely ignore the list of ports defined in the Dockerfile by NOT using '-P' (UPPERCASE)"
  info "     * or '--publish-all' flag when starting the container. Use the '-p' (lowercase) or '--publish' flag"
  info "     * to explicitly define the ports that you need for a particular container instance."
  logjson "5.8" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 5.9
check_5_9() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_9="5.9  - Ensure the host's network namespace is not shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    mode=$(docker inspect --format 'NetworkMode={{ .HostConfig.NetworkMode }}' "$c")

    if [ "$mode" = "NetworkMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_9"
        info "     * The networking mode on a container when set to '--net=host', skips placing the container inside"
        info "     * separate network stack. This would network-wise mean that the container lives 'outside'"
        info "     * in the main Docker host and has full access to its network interfaces."
        info "     * Avoid passing '-net=host' option when starting the container."
        info "     * Container running with networking mode 'host': $c"
        logjson "5.9" "FAIL: $c"
        fail=1
      else
        info "     * Container running with networking mode 'host': $c"
        logjson "5.9" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found no Network Mode host
  if [ $fail -eq 0 ]; then
      pass "$check_5_9"
      logjson "5.9" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.10
check_5_10() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_10="5.10 - Ensure memory usage for container is limited"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format '{{ .Config.Memory }}' "$c" 2> /dev/null 1>&2; then
      memory=$(docker inspect --format '{{ .Config.Memory }}' "$c")
    else
      memory=$(docker inspect --format '{{ .HostConfig.Memory }}' "$c")
    fi

    if [ "$memory" = "0" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_10"
        info "     * By default, all containers on a Docker host share the resources equally. By using the resource"
        info "     * management capabilities of Docker host, such as memory limit, you can control the amount of memory"
        info "     * that a container may consume."
        info "     * Run the container with only as much memory as required, using the '--memory' argument."
        info "     * e.g.:        docker run --interactive --tty --memory 256m centos /bin/bash"
        info "     * Container running without memory restrictions: $c"
        logjson "5.10" "FAIL: $c"
        fail=1
      else
        info "     * Container running without memory restrictions: $c"
        logjson "5.10" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found no lack of Memory restrictions
  if [ $fail -eq 0 ]; then
      pass "$check_5_10"
      logjson "5.10" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.11
check_5_11() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_11="5.11 - Ensure CPU priority is set appropriately on the container"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format '{{ .Config.CpuShares }}' "$c" 2> /dev/null 1>&2; then
      shares=$(docker inspect --format '{{ .Config.CpuShares }}' "$c")
    else
      shares=$(docker inspect --format '{{ .HostConfig.CpuShares }}' "$c")
    fi

    if [ "$shares" = "0" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_11"
        info "     * By default, all containers on a Docker host share the resources equally."
        info "     * CPU sharing allows to prioritize one container over the other and forbids the lower priority"
        info "     * container to claim CPU resources more often. This ensures that the high priority containers"
        info "     * are served better."
        info "     * To do so start the container using the '--cpu-shares' argument. (default 1024)"
        info "     * e.g.:        docker run --interactive --tty --cpu-shares 512 centos /bin/bash"
        info "     * Container running without CPU restrictions: $c"
        logjson "5.11" "FAIL: $c"
        fail=1
      else
        info "     * Container running without CPU restrictions: $c"
        logjson "5.11" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found no lack of CPUShare restrictions
  if [ $fail -eq 0 ]; then
      pass "$check_5_11"
      logjson "5.11" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.12
check_5_12() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_12="5.12 - Ensure the container's root filesystem is mounted as read only"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
   read_status=$(docker inspect --format '{{ .HostConfig.ReadonlyRootfs }}' "$c")

    if [ "$read_status" = "false" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_12"
        info "     * Enabling this option forces containers at runtime to explicitly define their data writing strategy"
        info "     * to persist or not persist their data. This also reduces security attack vectors since the container"
        info "     * instance's filesystem cannot be tampered with or written to unless it has explicit read-write"
        info "     * permissions on its filesystem folder and directories."
        info "     * e.g.:        docker run <Run arguments> --read-only <Container Image Name or ID> <Command>"
        info "     * Enabling the '--read-only' option at a container's runtime should be used by administrators to force"
        info "     * a container's executable processes to only write container data to explicit storage locations during"
        info "     * the container's runtime."
        info "     * Examples of explicit storage locations during a container's runtime include, but not limited to:"
        info "     *    1. Use the --tmpfs option to mount a temporary file system for non-persistent data writes."
        info "     *        docker run --interactive --tty --read-only --tmpfs "/run" --tmpfs "/tmp" centos /bin/bash"
        info "     *    2. Enabling Docker rw mounts at a container's runtime to persist container data directly"
        info "     *       on the Docker host filesystem." 
        info "     *        docker run --interactive --tty --read-only -v /opt/app/data:/run/app/data:rw centos /bin/bash"
        info "     *    3. Using Docker shared-storage volume plugins for Docker data volume to persist container data."
        info "     *        docker volume create -d convoy --opt o=size=20GB my-named-volume docker run --interactive"
        info "     *        --tty --read-only -v my-named-volume:/run/app/data centos /bin/bash"
        info "     * Container running with root FS mounted R/W: $c"
        logjson "5.12" "FAIL: $c"
        fail=1
      else
        info "     * Container running with root FS mounted R/W: $c"
        logjson "5.12" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found no R/W FS mounts
  if [ $fail -eq 0 ]; then
      pass "$check_5_12"
      logjson "5.12" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.13
check_5_13() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_13="5.13 -  Ensure incoming container traffic is binded to a specific host interface"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    for ip in $(docker port "$c" | awk '{print $3}' | cut -d ':' -f1); do
      if [ "$ip" = "0.0.0.0" ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          fail "$check_5_13"
          info "     * By default, Docker exposes the container ports on 0.0.0.0, the wildcard IP address"
          info "     * that will match any possible incoming network interface on the host machine."
          info "     * Bind the container port to a specific host interface on the desired host port."
          info "     * e.g.:    docker run --detach --publish 10.2.3.4:49153:80 nginx"
          info "     * In the example above, the container port 80 is bound to the host port on 49153"
          info "     * and would accept incoming connection only from 10.2.3.4 external interface"
          info "     * Port being bound to wildcard IP: $ip in $c"
          logjson "5.13" "FAIL: $ip in $c"
          fail=1
        else
          info "     * Port being bound to wildcard IP: $ip in $c"
          logjson "5.13" "FAIL: $ip in $c"
        fi
      fi
    done
  done
  # We went through all the containers and found no ports bound to 0.0.0.0
  if [ $fail -eq 0 ]; then
      pass "$check_5_13"
      logjson "5.13" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.14
check_5_14() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_14="5.14 - Ensure 'on-failure' container restart policy is set to '5'"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    policy=$(docker inspect --format MaximumRetryCount='{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' "$c")

    if [ "$policy" != "MaximumRetryCount=5" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_14"
        info "     * When running docker with '--restart', if you indefinitely keep trying to start the container,"
        info "     * it could possibly lead to a denial of service on the host."
        info "     * You should choose the on-failure restart policy and limit the restart attempts to 5."
        info "     * e.g.:    docker run --detach --restart=on-failure:5 nginx"
        info "     * MaximumRetryCount is not set to 5: $c"
        logjson "5.14" "FAIL: $c"
        fail=1
      else
        info "     * MaximumRetryCount is not set to 5: $c"
        logjson "5.14" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and they all had MaximumRetryCount=5
  if [ $fail -eq 0 ]; then
      pass "$check_5_14"
      logjson "5.14" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.15
check_5_15() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_15="5.15 - Ensure the host's process namespace is not shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    mode=$(docker inspect --format 'PidMode={{.HostConfig.PidMode }}' "$c")

    if [ "$mode" = "PidMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_15"
        info "     * If the host's PID namespace is shared with the container, it would basically allow processes"
        info "     * within the container to see all of the processes on the host system."
        info "     * Do not start a container with '--pid=host' argument."
        info "     * Host PID namespace being shared with: $c"
        logjson "5.15" "FAIL: $c"
        fail=1
      else
        info "     * Host PID namespace being shared with: $c"
        logjson "5.15" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with PidMode as host
  if [ $fail -eq 0 ]; then
      pass "$check_5_15"
      logjson "5.15" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.16
check_5_16() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_16="5.16 - Ensure the host's IPC namespace is not shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    mode=$(docker inspect --format 'IpcMode={{.HostConfig.IpcMode }}' "$c")

    if [ "$mode" = "IpcMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_16"
        info "     * Shared memory segments are used to accelerate inter-process communication."
        info "     * If the host's IPC (POSIX/SysV IPC) namespace is shared with the container, it would basically"
        info "     * allow processes within the container to see all of the IPC on the host system."
        info "     * Do not start a container with '--ipc=host' argument."
        info "     * Host IPC namespace being shared with: $c"
        logjson "5.16" "FAIL: $c"
        fail=1
      else
        info "     * Host IPC namespace being shared with: $c"
        logjson "5.16" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with IPCMode as host
  if [ $fail -eq 0 ]; then
      pass "$check_5_16"
      logjson "5.16" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.17
check_5_17() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_17="5.17 - Ensure host devices are not directly exposed to containers"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    devices=$(docker inspect --format 'Devices={{ .HostConfig.Devices }}' "$c")

    if [ "$devices" != "Devices=" -a "$devices" != "Devices=[]" -a "$devices" != "Devices=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn "$check_5_17"
        info "     * Avoid directly exposing host devices to containers, especially for containers that are not trusted."
        info "     * If you still would want to expose the host device to a container, use the sharing permissions"
        info "     * appropriately:   r - read only / w - writable / m - mknod allowed."
        info "     * e.g.:    docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rw"
        info "     *          --device=/dev/temp_sda:/dev/temp_sda:r centos bash"
        info "     * Container has devices exposed directly: $c"
        logjson "5.17" "WARN: $c"
        fail=1
      else
        info "     * Container has devices exposed directly: $c"
        logjson "5.17" "WARN: $c"
      fi
    fi
  done
  # We went through all the containers and found none with devices
  if [ $fail -eq 0 ]; then
      pass "$check_5_17"
      logjson "5.17" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
  fi
}

# 5.18
check_5_18() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_18="5.18 - Ensure the default ulimit is overwritten at runtime, only if needed"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    ulimits=$(docker inspect --format 'Ulimits={{ .HostConfig.Ulimits }}' "$c")

    if [ "$ulimits" = "Ulimits=" -o "$ulimits" = "Ulimits=[]" -o "$ulimits" = "Ulimits=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn "$check_5_18"
        info "     * 'ulimit' provides control over the resources available to the shell and to processes started by it."
        info "     * If the default 'ulimit' settings are not appropriate for a particular container instance, you may"
        info "     * override them as an exception. If most of the container instances are overriding default 'ulimit'"
        info "     * settings, consider changing the default 'ulimit' settings to something that is appropriate"
        info "     * for your needs."
        info "     * e.g. override:    docker run --ulimit nofile=1024:1024 --interactive --tty centos /bin/bash"
        info "     * N.B.: Container instances inherit the default ulimit settings set at the Docker daemon level."
        info "     * Container no default ulimit override: $c"
        logjson "5.18" "WARN: $c"
        fail=1
      else
        info "     * Container no default ulimit override: $c"
        logjson "5.18" "WARN: $c"
      fi
    fi
  done
  # We went through all the containers and found none without Ulimits
  if [ $fail -eq 0 ]; then
      pass "$check_5_18"
      logjson "5.18" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
  fi
}

# 5.19
check_5_19() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_19="5.19 - Ensure mount propagation mode is not set to shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format 'Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' "$c" | \
     grep shared 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_19"
        info "     * Mounting a volume in shared mode does not restrict any other container to mount and make changes"
        info "     * to that volume. This might be catastrophic if the mounted volume is sensitive to changes. "
        info "     * Do not set mount propagation mode to shared until needed."
        info "     * For example, do not start container as below: "
        info "     *        docker run <Run arguments> --volume=/hostPath:/containerPath:shared "
        info "     *        <Container Image Name or ID> <Command>"
        info "     * Mount propagation mode is shared: $c"
        logjson "5.19" "FAIL: $c"
        fail=1
      else
        info "     * Mount propagation mode is shared: $c"
        logjson "5.19" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with shared propagation mode
  if [ $fail -eq 0 ]; then
      pass "$check_5_19"
      logjson "5.19" "PASS"
      currentScore=$((currentScore + 1))
  else
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 5.20
check_5_20() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_20="5.20 - Ensure the host's UTS namespace is not shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    mode=$(docker inspect --format 'UTSMode={{.HostConfig.UTSMode }}' "$c")

    if [ "$mode" = "UTSMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_20"
        info "     * Sharing the UTS namespace with the host provides full permission to the container to change"
        info "     * the hostname of the host. This is insecure and should not be allowed."
        info "     * Do not start a container with '--uts=host' argument."
        info "     * Host UTS namespace being shared with: $c"
        logjson "5.20" "FAIL: $c"
        fail=1
      else
        info "     * Host UTS namespace being shared with: $c"
        logjson "5.20" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with UTSMode as host
  if [ $fail -eq 0 ]; then
      pass "$check_5_20"
      logjson "5.20" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.21
check_5_21() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_21="5.21 - Ensure the default seccomp profile is not Disabled"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format 'SecurityOpt={{.HostConfig.SecurityOpt }}' "$c" | \
      grep -E 'seccomp:unconfined|seccomp=unconfined' 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_21"
        info "     * Most of the applications do not need all the system calls and thus benefit by having a reduced set"
        info "     * of available system calls. The reduced set of system calls reduces the total kernel surface exposed"
        info "     * to the application and thus improvises application security."
        info "     * By default, seccomp profiles are enabled. You do not need to do anything unless you want to modify"
        info "     * and use the modified seccomp profile (e.g. using '--security-opt=seccomp:unconfined')"
        info "     * Default seccomp profile disabled: $c"
        logjson "5.21" "FAIL: $c"
        fail=1
      else
        info "     * Default seccomp profile disabled: $c"
        logjson "5.21" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with default secomp profile disabled
  if [ $fail -eq 0 ]; then
      pass "$check_5_21"
      logjson "5.21" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.22
check_5_22() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_22="5.22 - Ensure docker exec commands are not used with privileged option"
  totalChecks=$((totalChecks + 1))
  note "$check_5_22"
  info "     * Using '--privileged' option in 'docker exec' gives extended Linux capabilities to the command. "
  info "     * This could potentially be insecure and unsafe to do especially when you are running containers"
  info "     * with dropped capabilities or with enhanced restrictions"
  logjson "5.22" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 5.23
check_5_23() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_23="5.23 - Ensure docker exec commands are not used with user option"
  totalChecks=$((totalChecks + 1))
  note "$check_5_23"
  info "     * Using '--user' option in 'docker exec' executes the command within the container as that user. "
  info "     * This could potentially be insecure and unsafe to do especially when you are running containers"
  info "     * with dropped capabilities or with enhanced restrictions."
  logjson "5.23" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 5.24
check_5_24() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_24="5.24 - Ensure cgroup usage is confirmed"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    mode=$(docker inspect --format 'CgroupParent={{.HostConfig.CgroupParent }}x' "$c")

    if [ "$mode" != "CgroupParent=x" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_24"
        info "     * System administrators typically define cgroups under which containers are supposed to run. "
        info "     * Even if cgroups are not explicitly defined by the system administrators, containers run under"
        info "     * docker cgroup by default."
        info "     * Do not use '--cgroup-parent' option in docker run command unless needed."
        logjson "5.24" "FAIL: $c"
        fail=1
      else
        info "     * Confirm cgroup usage: $c"
        logjson "5.24" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with UTSMode as host
  if [ $fail -eq 0 ]; then
      pass "$check_5_24"
      logjson "5.24" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.25
check_5_25() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi
  check_5_25="5.25 - Ensure the container is restricted from acquiring additional privileges"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if ! docker inspect --format 'SecurityOpt={{.HostConfig.SecurityOpt }}' "$c" | grep 'no-new-privileges' 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_25"
        info "     * Container(s) not restricted from acquiring additional privileges via suid or sgid bits."
        info "     * A process can set the 'no_new_priv' bit in the kernel. It persists across fork, clone and execve."
        info "     * The 'no_new_priv' bit ensures that the process or its children processes do not gain any additional"
        info "     * privileges via suid or sgid bits."
        info "     * e.g.     docker run --rm -it --security-opt=no-new-privileges ubuntu bash"
        info "     * BEWARE: 'no_new_priv' prevents LSMs like SELinux from transitioning to process labels that have"
        info "     * access not allowed to the current process."
        info "     * Privileges not restricted: $c"
        logjson "5.25" "FAIL: $c"
        fail=1
      else
        info "     * Privileges not restricted: $c"
        logjson "5.25" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with capability to acquire additional privileges
  if [ $fail -eq 0 ]; then
      pass "$check_5_25"
      logjson "5.25" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.26
check_5_26() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_26="5.26 - Ensure container health is checked at runtime"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if ! docker inspect --format '{{ .Id }}: Health={{ .State.Health.Status }}' "$c" 2>/dev/null 1>&2; then
      if [ $fail -eq 0 ]; then
        fail "$check_5_26"
        info "     * If the container image does not have an HEALTHCHECK instruction defined, use '--health-cmd'"
        info "     * parameter at container runtime for checking container health."
        info "     * e.g.:      docker run -d --health-cmd='stat /etc/passwd || exit 1' nginx"
        info "     * By default, health checks are not done at container runtime."
        info "     * Health check not set: $c"
        logjson "5.26" "FAIL: $c"
        fail=1
      else
        info "     * Health check not set: $c"
        logjson "5.26" "FAIL: $c"
      fi
    fi
  done
  if [ $fail -eq 0 ]; then
      pass "$check_5_26"
      logjson "5.26" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.27
check_5_27() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_27="5.27 - Ensure docker commands always get the latest version of the image"
  totalChecks=$((totalChecks + 1))
  note "$check_5_27"
  info "     * Always ensure that you are using the latest version of the image within your repository"
  info "     * and not the cached older versions by using a proper version pinning mechanism."
  info "     * Ref.:  https://github.com/docker/docker/pull/16609"
  logjson "5.27" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 5.28
check_5_28() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_28="5.28 - Ensure PIDs cgroup limit is used"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    pidslimit=$(docker inspect --format '{{.HostConfig.PidsLimit }}' "$c")

    if [ "$pidslimit" -le 0 ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_28"
        info "     * PIDs cgroup '--pids-limit' will prevent attackers from launching a fork bomb with a single command"
        info "     * inside the container attacks by restricting the number of forks that can happen inside a container"
        info "     * at a given time."
        info "     * e.g.:     docker run -it --pids-limit 100 <Image_ID>"
        info "     * PIDs limit not set: $c"
        logjson "5.28" "FAIL: $c"
        fail=1
      else
        info "     * PIDs limit not set: $c"
        logjson "5.28" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found all with PIDs limit
  if [ $fail -eq 0 ]; then
      pass "$check_5_28"
      logjson "5.28" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.29
check_5_29() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_29="5.29 - Ensure Docker's default bridge docker0 is not used"
  totalChecks=$((totalChecks + 1))

  fail=0
  networks=$(docker network ls -q 2>/dev/null)
  for net in $networks; do
    if docker network inspect --format '{{ .Options }}' "$net" 2>/dev/null | grep "com.docker.network.bridge.name:docker0" >/dev/null 2>&1; then
      docker0Containers=$(docker network inspect --format='{{ range $k, $v := .Containers }} {{ $k }} {{ end }}' "$net" | \
        sed -e 's/^ //' -e 's/  /\n/g' 2>/dev/null)

        if [ -n "$docker0Containers" ]; then
          if [ $fail -eq 0 ]; then
            warn "$check_5_29"
            info "     * Docker connects virtual interfaces created in the bridge mode to a common bridge called docker0."
            info "     * This default networking model is vulnerable to ARP spoofing and MAC flooding attacks since"
            info "     * there is no filtering applied."
            info "     * Follow Docker documentation and setup a user-defined network. "
            info "     * Run all the containers in the defined network."
            info "     * Ref.: https://docs.docker.com/engine/userguide/networking/"
            logjson "5.29" "WARN"
            fail=1
          fi
          for c in $docker0Containers; do
            if [ -z "$exclude" ]; then
              cName=$(docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's/\///g')
            else
              pattern=$(echo "$exclude" | sed 's/,/|/g')
              cName=$(docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's/\///g' | grep -Ev "$pattern" )
            fi
            if ! [ -z "$cName" ]; then
              info "     * Container in docker0 network: $cName"
              logjson "5.29" "WARN: $c"
            fi
          done
        fi
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  done
  # We went through all the containers and found none in docker0 network
  if [ $fail -eq 0 ]; then
      pass "$check_5_29"
      logjson "5.29" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 0))
      warnChecks=$((warnChecks + 1))
  fi
}

# 5.30
check_5_30() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_30="5.30 - Ensure the host's user namespaces is not shared"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format '{{ .HostConfig.UsernsMode }}' "$c" 2>/dev/null | grep -i 'host' >/dev/null 2>&1; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_30"
        info "     * Do not share the host's user namespaces with the containers."
        info "     * User namespaces ensure that a root process inside the container will be mapped"
        info "     * to a non-root process outside the container."
        info "     * e.g. do not run:     docker run --rm -it --userns=host ubuntu bash"
        info "     * Namespace shared: $c"
        logjson "5.30" "FAIL: $c"
        fail=1
      else
        info "     * Namespace shared: $c"
        logjson "5.30" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with host's user namespace shared
  if [ $fail -eq 0 ]; then
      pass "$check_5_30"
      logjson "5.30" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}

# 5.31
check_5_31() {
  if [ "$running_containers" -ne 1 ]; then
    return
  fi

  check_5_31="5.31 - Ensure the Docker socket is not mounted inside any containers"
  totalChecks=$((totalChecks + 1))

  fail=0
  for c in $containers; do
    if docker inspect --format '{{ .Mounts }}' "$c" 2>/dev/null | grep 'docker.sock' >/dev/null 2>&1; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail "$check_5_31"
        info "     * If the docker socket is mounted inside a container it would allow processes running within the container to execute"
        info "     * docker commands which effectively allows for full control of the host."
        info "     * Ensure that no containers mount 'docker.sock' as a volume."
        info "     * (not mounted by default)"
        info "     * Docker socket shared: $c"
        logjson "5.31" "FAIL: $c"
        fail=1
      else
        info "     * Docker socket shared: $c"
        logjson "5.31" "FAIL: $c"
      fi
    fi
  done
  # We went through all the containers and found none with docker.sock shared
  if [ $fail -eq 0 ]; then
      pass "$check_5_31"
      logjson "5.31" "PASS"
      currentScore=$((currentScore + 1))
  else
      currentScore=$((currentScore - 1))
      failChecks=$((failChecks + 1))
  fi
}
