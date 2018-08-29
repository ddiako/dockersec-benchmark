#!/bin/sh

images=$(docker images -q)

check_4() {
  logit "\n"
  chkclass "4 - Container Images and Build File"
}

# 4.1
check_4_1() {
  check_4_1="4.1  - Ensure a user for the container has been created"
  totalChecks=$((totalChecks + 1))

  # If container_users is empty, there are no running containers
  if [ -z "$containers" ]; then
    note "$check_4_1"
    info "     * No containers running"
    logjson "4.1" "NOTE"
    currentScore=$((currentScore + 0))
    noteChecks=$((noteChecks + 1))
  else
    # We have some containers running, set failure flag to 0. Check for Users.
    fail=0
    # Make the loop separator be a new-line in POSIX compliant fashion
    set -f; IFS=$'
  '
    for c in $containers; do
      user=$(docker inspect --format 'User={{.Config.User}}' "$c")

      if [ "$user" = "User=" -o "$user" = "User=[]" -o "$user" = "User=<no value>" ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          fail "$check_4_1"
          info "     *    Running as root: $c"
          logjson "4.1" "FAIL: $c"
          fail=1
        else
          info "     *    Running as root: $c"
          logjson "4.1" "FAIL: $c"
        fi
      fi
    done
    # We went through all the containers and found none running as root
    if [ $fail -eq 0 ]; then
        pass "$check_4_1"
        logjson "4.1" "PASS"
        currentScore=$((currentScore + 1))
    else
        currentScore=$((currentScore - 1))
        failChecks=$((failChecks + 1))
    fi
  fi
  # Make the loop separator go back to space
  set +f; unset IFS
}

# 4.2
check_4_2() {
  check_4_2="4.2  - Ensure that containers use trusted base images"
  totalChecks=$((totalChecks + 1))
  note "$check_4_2"
  logjson "4.2" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 4.3
check_4_3() {
  check_4_3="4.3  - Ensure unnecessary packages are not installed in the container"
  totalChecks=$((totalChecks + 1))
  note "$check_4_3"
  logjson "4.3" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 4.4
check_4_4() {
  check_4_4="4.4  - Ensure images are scanned and rebuilt to include security patches"
  totalChecks=$((totalChecks + 1))
  note "$check_4_4"
  logjson "4.4" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 4.5
check_4_5() {
  check_4_5="4.5  - Ensure Content trust for Docker is Enabled"
  totalChecks=$((totalChecks + 1))
  if [ "x$DOCKER_CONTENT_TRUST" = "x1" ]; then
    pass "$check_4_5"
    logjson "4.5" "PASS"
    currentScore=$((currentScore + 1))
  else
    warn "$check_4_5"
    info "     * Content trust provides the ability to use digital signatures for data"
    info "     * sent to and received from remote Docker registries."
    info "     * This ensures provenance of container images."
    info "     * To enable content trust in a bash shell, enter the following command: "
    info "     *            export DOCKER_CONTENT_TRUST=1"
    info "     * (can be added to your bash profile to be enabled on every login)"
    info "     * Note that you are required to follow trust procedures while working "
    info "     * with images - 'build', 'create', 'pull', 'push' and 'run'."
    info "     * N.B.: Only available for users of the public Docker Hub !"
    info "     * (not available for the Docker Trusted Registry or for private registries)"
    logjson "4.5" "WARN"
    currentScore=$((currentScore - 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 4.6
check_4_6() {
  check_4_6="4.6  - Ensure HEALTHCHECK instructions have been added to the container image"
  totalChecks=$((totalChecks + 1))
  fail=0
  for img in $images; do
    if docker inspect --format='{{.Config.Healthcheck}}' "$img" 2>/dev/null | grep -e "<nil>" >/dev/null 2>&1; then
      if [ $fail -eq 0 ]; then
        fail=1
        fail "$check_4_6"
        logjson "4.6" "FAIL"
      fi
      imgName=$(docker inspect --format='{{.RepoTags}}' "$img" 2>/dev/null)
      if ! [ "$imgName" = '[]' ]; then
        info "     *    No Healthcheck found: $imgName"
        logjson "4.6" "FAIL: $imgName"
      fi
    fi
  done
  if [ $fail -eq 0 ]; then
    pass "$check_4_6"
    logjson "4.6" "PASS"
    currentScore=$((currentScore + 1))
  else
    info "     * Health status allows Docker to detect non-working containers then exit them or instantiate new ones."
    info "     * Not activated by default. To activate it, please refer to:"
    info "     *    - https://docs.docker.com/engine/reference/builder/#healthcheck"
    currentScore=$((currentScore - 1))
    failChecks=$((failChecks + 1))
  fi
}

# 4.7
check_4_7() {
  check_4_7="4.7  - Ensure update instructions are not use alone in the Dockerfile"
  totalChecks=$((totalChecks + 1))
  fail=0
  for img in $images; do
    if docker history "$img" 2>/dev/null | grep -e "update" >/dev/null 2>&1; then
      if [ $fail -eq 0 ]; then
        fail=1
        # WARNING level because in a controled environement, updates could be prohibed
        warn "$check_4_7"
        info "     * Do not use update instructions such as apt-get update alone"
        info "     * or in a single line in the Dockerfile. This could potentially deny any fresh"
        info "     * updates to go in the later builds."
        logjson "4.7" "WARN"
        warnChecks=$((warnChecks + 1))
      fi
      imgName=$(docker inspect --format='{{.RepoTags}}' "$img" 2>/dev/null)
      if ! [ "$imgName" = '[]' ]; then
        info "     *    Update instruction found: $imgName"
      fi
    fi
  done
  if [ $fail -eq 0 ]; then
    pass "$check_4_7"
    logjson "4.7" "PASS"
    currentScore=$((currentScore + 1))
  else
    info "     * Use update instructions along with install instructions (or any other) and version pinning"
    info "     * for packages while installing them. This would bust the cache and force to extract the required versions."
    info "     * Alternatively,you could use '--no-cache' flag during 'docker build' process to avoid using cached layers."
    currentScore=$((currentScore + 0))
    warnChecks=$((warnChecks + 1))
  fi
}

# 4.8
check_4_8() {
  check_4_8="4.8  - Ensure setuid and setgid permissions are removed in the images"
  totalChecks=$((totalChecks + 1))
  note "$check_4_8"
  info "     * Run the below command on the image to list the executables having setuid and setgid permissions:"
  info "     *          docker run <Image_ID> find / -perm +6000 -type f -exec ls -ld {} \; 2> /dev/null"
  info "     * Carefully, review the list and allow 'setuid' and 'setgid' only on executables which need them."
  info "     * You could remove these permissions during build time by adding the following command in your Dockerfile,"
  info "     * preferably towards the end of the Dockerfile (TO ADAPT TO YOUR REVIEW -- CAN BREAK LEGITIM EXECUTABLES): "
  info "     *          RUN find / -perm +6000 -type f -exec chmod a-s {} \; || true"
  logjson "4.8" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 4.9
check_4_9() {
  check_4_9="4.9  - Ensure COPY is used instead of ADD in Dockerfile"
  totalChecks=$((totalChecks + 1))
  fail=0
  for img in $images; do
    docker history "$img" 2> /dev/null | grep 'ADD' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      if [ $fail -eq 0 ]; then
        fail=1
        warn "$check_4_9"
        info "     * 'COPY' instruction just copies the files from the local host machine to the container file system."
        info "     * 'ADD' instruction potentially could retrieve files from remote URLs and perform operations such as" 
        info "     * unpacking. Thus, ADD instruction introduces risks such as adding malicious files from URLs without"
        info "     * scanning and unpacking procedure vulnerabilities."
        logjson "4.9" "WARN"

      fi
      imgName=$(docker inspect --format='{{.RepoTags}}' "$img" 2>/dev/null)
      if ! [ "$imgName" = '[]' ]; then
        info "     *    ADD in image history: $imgName"
        logjson "4.9" "WARN: $imgName"
      fi
      currentScore=$((currentScore + 0))
      warnChecks=$((warnChecks + 1))
    fi
  done
  if [ $fail -eq 0 ]; then
    pass "$check_4_9"
    logjson "4.9" "PASS"
    currentScore=$((currentScore + 1))
  fi
}

# 4.10
check_4_10() {
  check_4_10="4.10 - Ensure secrets are not stored in Dockerfiles"
  totalChecks=$((totalChecks + 1))
  warn "$check_4_10"
  info "     * Docker commands such as 'docker history' and various tools and utilities can disclose secrets"
  info "     * included in Dockerfiles. You should identify a way to handle secrets for your Docker images."
  logjson "4.10" "WARN"
  currentScore=$((currentScore + 0))
  warnChecks=$((warnChecks + 1))
}

# 4.11
check_4_11() {
  check_4_11="4.11 - Ensure verified packages are only Installed"
  totalChecks=$((totalChecks + 1))
  note "$check_4_11"
  info "     * Verify that GPG keys or other secure package distribution mechanism is used to install the image."
  info "     * Tampered packages could potentially be malicious or have some known vulnerabilities"
  info "     * that could be exploited."
  info "     * Can be verified with:"
  info "     *        docker history <Image_ID>"
  logjson "4.11" "NOTE"
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}
