#!/bin/bash

xc() # $@-args
{
  cecho "$@"
  "$@"
}
cecho() # $@-args
{
  awk '
  BEGIN {
    x = "\047"
    printf "\033[32m"
    while (++i < ARGC) {
      if (! (y = split(ARGV[i], z, x))) {
        printf (x x)
      } else {
        for (j = 1; j <= y; j++) {
          printf "%s", z[j] ~ /[^[:alnum:]%+,./:=@_-]/ ? (x z[j] x) : z[j]
          if (j < y) printf "\\" x
        }
      }
      printf i == ARGC - 1 ? "\033[m\n" : FS
    }
  }
  ' "$@"
}