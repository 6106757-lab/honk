Internal

- The 6.6 routing tests now load the WAN egress TC entry classifier and assert that the entry plus both tail-call targets are loaded before driving BPF_PROG_TEST_RUN, instead of failing on a NotLoaded program.
