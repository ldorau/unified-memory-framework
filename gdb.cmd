set breakpoint pending on

b arena_extent_alloc
b arena_extent_dalloc
b arena_extent_destroy
b arena_extent_commit
b arena_extent_decommit
b arena_extent_purge_lazy
b arena_extent_purge_forced
b arena_extent_split
b arena_extent_merge

r 


# backtrace of 1st arena_extent_alloc
bt


c


# backtrace of arena_extent_split
bt


c


# backtrace of 2nd arena_extent_alloc
bt


c


# backtrace of arena_extent_dalloc
bt


q
y
