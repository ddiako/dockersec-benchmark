#!/bin/sh

check_6() {
  logit "\n"
  chkclass "6 - Docker Security Operations"
}

# 6.1
check_6_1() {
  check_6_1="6.1  - Avoid image sprawl"
  totalChecks=$((totalChecks + 1))
  images=$(docker images -q | sort -u | wc -l | awk '{print $1}')
  active_images=0

  for c in $(docker inspect --format "{{.Image}}" $(docker ps -qa) 2>/dev/null); do
    if docker images --no-trunc -a | grep "$c" > /dev/null ; then
      active_images=$(( active_images += 1 ))
    fi
  done

    note "$check_6_1"
    info "     * Do not keep a large number of container images on the same host. Use only tagged images as appropriate."
    info "     * Keep the set of the images that you actually need and establish a workflow to remove old or stale images from the host."
    info "     * Additionally, use features such as pull-by-digest to get specific images from the registry."
    info "     * Images and layered filesystems remain accessible on the host until the administrator removes all tags that refer"
    info "     * to those images or layers."
    info "     * There are currently: $images images"

  if [ "$active_images" -lt "$((images / 2))" ]; then
    info "     * Only $active_images out of $images are in use"
    logjson "6.1" "NOTE: $active_images"
  fi
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}

# 6.2
check_6_2() {
  check_6_2="6.2  - Avoid container sprawl"
  totalChecks=$((totalChecks + 1))
  total_containers=$(docker info 2>/dev/null | grep "^Containers" | awk '{print $2}')
  running_containers=$(docker ps -q | wc -l | awk '{print $1}')
  diff="$((total_containers - running_containers))"
  if [ "$diff" -gt 25 ]; then
    note "$check_6_2"
    info "     * The flexibility of containers makes it easy to run multiple instances of applications and indirectly leads to Docker images"
    info "     * that exist at varying security patch levels. It also means that you are consuming host resources that otherwise could have been"
    info "     * used for running 'useful' containers. Having more than just the manageable number of containers on a particular host makes"
    info "     * the situation vulnerable to mishandling, misconfiguration and fragmentation. Thus, avoid container sprawl and keep the number"
    info "     * of containers on a host to a manageable total."
    info "     * Periodically check your container inventory per host and clean up the stopped containers using the below command:"
    info "     *         docker container prune"
    info "     * There are currently a total of $total_containers containers, with only $running_containers of them currently running"
    logjson "6.2" "NOTE: $running_containers"
  else
    note "$check_6_2"
    info "     * There are currently a total of $total_containers containers, with $running_containers of them currently running"
    logjson "6.2" "NOTE: $running_containers"
  fi
  currentScore=$((currentScore + 0))
  noteChecks=$((noteChecks + 1))
}
