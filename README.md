# NOVA: NOn-Volatile memory Accelerated log-structured file system


NOVA's goal is to provide a high-performance, full-featured, production-ready
file system tailored for byte-addressable non-volatile memories (e.g., NVDIMMs
and Intel's soon-to-be-released 3DXpoint DIMMs).  It combines design elements
from many other file systems to provide a combination of high-performance,
strong consistency guarantees, and comprehensive data protection.  NOVA support
DAX-style mmap and making DAX performs well is a first-order priority in NOVA's
design.  NOVA was developed by the [Non-Volatile Systems Laboratory][NVSL] in
the [Computer Science and Engineering Department][CSE] at the [University of
California, San Diego][UCSD].


NOVA is primarily a log-structured file system, but rather than maintain a
single global log for the entire file system, it maintains separate logs for
each file (inode).  NOVA breaks the logs into 4KB pages, they need not be
contiguous in memory.  The logs only contain metadata.

File data pages reside outside the log, and log entries for write operations
point to data pages they modify.  File modification uses copy-on-write (COW) to
provide atomic file updates.

For file operations that involve multiple inodes, NOVA use small, fixed-sized
redo logs to atomically append log entries to the logs of the inodes involned.

This structure keeps logs small and make garbage collection very fast.  It also
enables enormous parallelism during recovery from an unclean unmount, since
threads can scan logs in parallel.

NOVA replicates and checksums all metadata structures and protects file data
with RAID-5-style parity.  It supports checkpoints to facilitate backups.

A more thorough discussion of NOVA's design is avaialable in these two papers:

**NOVA: A Log-structured File system for Hybrid Volatile/Non-volatile Main Memories** 
[PDF](http://cseweb.ucsd.edu/~swanson/papers/FAST2016NOVA.pdf)<br>
*Jian Xu and Steven Swanson*<br>
Published in [FAST 2016][FAST2016]

**Hardening the NOVA File System**
[PDF](http://cseweb.ucsd.edu/~swanson/papers/TechReport2017HardenedNOVA.pdf) <br>
UCSD-CSE Techreport CS2017-1018
*Jian Xu, Lu Zhang, Amirsaman Memaripour, Akshatha Gangadharaiah, Amit Borase, Tamires Brito Da Silva, Andy Rudoff, Steven Swanson*<br>

Read on for further details about NOVA's overall design and its current status 

### Compatibilty with Other File Systems

NOVA aims to be compatible with other Linux file systems.  To help verify that it achieves this we run several test suites against NOVA each night.

* The latest version of XFSTests.
* The linux testing project file system tests.
* The fstest POSIX conformance test suite.

Currently, nearly all of these tests pass for the `master` branch, and the
handful of failures are not critical and are on our list of TODOs.

NOVA uses the standard PMEM kernel interfaces for accessing and managing persistent memory.

### Atomicity

By default, NOVA makes all metadata and file data operations atomic.

Strong atomicity guarantees make it easier to build reliable applications on
NOVA, and NOVA can provide these guarantees with sacrificing much performance
because NVDIMMs support very fast random access.

NOVA also supports "unsafe data" and "unsafe metadata" modes that
improve performance in some cases and allows for non-atomic updates of file
data and metadata, respectively.

### Data Protection

NOVA aims to protect data against both misdirected writes in the kernel (which
can easily "scribble" over the contents of an NVDIMM) as well as media errors.

NOVA protects all of its metadata data structures with a combination of
replication and checksums.  It protects file data using RAID-5 style parity.

NOVA can detects data corruption by verifying checksums on each access and by
catching and handling machine check exceptions (MCEs) that arise when the
system's memory controller detects at uncorrectable media error.

We use a fault injection tool that allows testing of these recovery mechanisms.

To facilitate backups, NOVA can take snapshots of the current filesystem state
that can be mounted read-only while the current file system is mounted
read-write.

The tech report list above describes the design of NOVA's data protection system in detail.

### DAX Support

Supporting DAX efficiently is a core feature of NOVA and one of the challenges
in designing NOVA is reconciling DAX support which aims to avoid file system
intervention when file data changes, and other features that require such
intervention.

NOVA's philosophy with respect to DAX is that when a program uses DAX mmap to
to modify a file, the program must take full responsibility for that data and
NOVA must ensure that the memory will behave as expected.  At other times, the
file system provides protection.  This approach has several implications:

1. Implementing `msync()` in user space works fine.

2. While a file is mmap'd, it is not protected by NOVA's RAID-style parity
mechanism, because protecting it would be too expensive.  When the file is
unmapped and/or during file system recovery, protection is restored.

3. The snapshot mechanism must be careful about the order in which in adds
pages to the file's snapshot image.

### Performance

The research paper and technical report referenced above compare NOVA's
performance to other file systems.  In almost all cases, NOVA outperforms other
DAX-enabled file systems.  A notable exception is sub-page updates which incur
COW overheads for the entire page.

The technical report also illustrates the trade-offs between our protection
mechanisms and performance.

## Gaps and Missing Features

Although NOVA is a fully-functional file system, there is still much work left
to be done.  In particular, (at least) the following items are currently missing:

1.  There is no mkfs or fsk utility (`mount` takes an option to create a NOVA file system)
2.  NOVA doesn't scrub data to prevent corruption from accumulating in infrequently accessed data.
3.  NOVA doesn't read bad block information on mount and attempt recovery of the effected data.
4.  NOVA only works on x86-64 kernels.
5.  NOVA does not currently support extended attributes or ACL.
6.  NOVA does not currently prevent writes to mounted snapshots.
7.  Using `write()` to modify pages that are mmap'd is not supported.
8.  ...


## Building and Using NOVA

This repo contains a version of the Linux with NOVA included.  You should be
able to build and install it just as you would the mainline Linux source.

### Building NOVA

To build NOVA, build the kernel with PMEM (`CONFIG_BLK_DEV_PMEM`), DAX (`CONFIG_FS_DAX`) and NOVA (`CONFIG_NOVA_FS`) support.  Install as usual.

### Running NOVA

NOVA runs on a pmem non-volatile memory region.  You can create one of these
regions with the `memmap` kernel command line option.  For instance, adding
`memmap=16G!8G` to the kernel boot parameters will reserve 16GB memory starting
from address 8GB, and the kernel will create a `pmem0` block device under the
`/dev` directory.

After the OS has booted, you can initialize a NOVA instance with the following commands:

~~~
#modprobe nova
#mount -t NOVA -o init /dev/pmem0 /mnt/ramdisk
~~~

The above commands create a NOVA instance on pmem0 device, and mount on `/mnt/ramdisk`.

To recover an existing NOVA instance, mount NOVA without the init option, for example:

~~~
#mount -t NOVA /dev/pmem0 /mnt/ramdisk
~~~

### Taking Snapshots

To create a snapshot:

~~~
#echo 1 > /proc/fs/NOVA/<device>/create_snapshot
~~~

To list the current snapshots:

~~~
#cat /proc/fs/NOVA/<device>/snapshots
~~~

To delete a snapshot, specify the snapshot index which is given by the previous command:

~~~
#echo <index> > /proc/fs/NOVA/<device>/delete_snapshot
~~~

To mount a snapshot, mount NOVA and specifying the snapshot index, for example:

~~~
#mount -t NOVA -o snapshot=<index> /dev/pmem0 /mnt/ramdisk
~~~

Users should not write to the file system after mounting a snapshot.

## Hacking and Contributing

The NOVA source code is almost completely contains in the `fs/nova` directory.
The execptions are some small changes in the kernel's memory management system
to support checkpointing.

`Documentation/filesystems/nova` contains a brief description of the role of
each file does in `fs/nova`.

If you find bugs, please [report them](https://github.com/NVSL/linux-nova/issues).

If you have other questions or suggestions you can contact the NOVA developers at [cse-nova-hackers@eng.ucsd.edu](mailto:cse-nova-hackers@eng.ucsd.edu).


[NVSL]: http://nvsl.ucsd.edu/ "http://nvsl.ucsd.edu"
[POSIXtest]: http://www.tuxera.com/community/posix-test-suite/ 
[FAST2016]: https://www.usenix.org/conference/fast16/technical-sessions
[CSE]: http://cs.ucsd.edu
[UCSD]: http://www.ucsd.edu