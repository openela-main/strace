Summary: Tracks and displays system calls associated with a running process
Name: strace
Version: 5.18
Release: 2%{?dist}
# The test suite is GPLv2+, all the rest is LGPLv2.1+.
License: LGPL-2.1+ and GPL-2.0+
Group: Development/Debuggers
URL: https://strace.io/
Source: https://strace.io/files/%{version}/%{name}-%{version}.tar.xz

BuildRequires: libacl-devel time gcc gzip make
BuildRequires: pkgconfig(bluez)
BuildRequires: elfutils-devel binutils-devel
BuildRequires: libselinux-devel

## Reported by covscan
## v5.2-3-g7ada13f "evdev: avoid bit vector decoding on non-successful and 0 return codes"
#Patch30: 0030-evdev-avoid-bit-vector-decoding-on-non-successful-an.patch
## v5.2-4-g96194ed "evdev: fix array size calculation in decode_bitset_"
#Patch31: 0031-evdev-fix-array-size-calculation-in-decode_bitset_.patch

### Pre-requisite for "tests: test evdev bitset decoding more thoroughly"
## v4.25~89 "tests: check decoding of successful evdev ioctl"
#Patch32: 0032-tests-check-decoding-of-successful-evdev-ioctl.patch

## Test for patches "evdev: avoid bit vector decoding on non-successful and 0
## return codes" and "evdev: fix array size calculation in decode_bitset_"
## v5.2-5-gcdd8206 "tests: test evdev bitset decoding more thoroughly"
#Patch33: 0033-tests-test-evdev-bitset-decoding-more-thoroughly.patch

### https://bugzilla.redhat.com/1747475 https://bugzilla.redhat.com/1747514
## v4.26~65 "s390x: beautify sthyi data tail prints"
#Patch34: 0034-s390x-beautify-sthyi-data-tail-prints.patch

## Reported by covscan (https://bugzilla.redhat.com/1747524
## https://bugzilla.redhat.com/1747526 https://bugzilla.redhat.com/1747530)
## v5.2-84-g91281fec "v4l2: avoid shifting left a signed number by 31 bit"
#Patch35: 0035-v4l2-avoid-shifting-left-a-signed-number-by-31-bit.patch
## v5.2~21 "syscall.c: avoid infinite loop in subcalls parsing"
#Patch36: 0036-syscall.c-avoid-infinite-loop-in-subcalls-parsing.patch
## v5.2~19 "kvm: avoid bogus vcpu_info assignment in vcpu_register"
#Patch37: 0037-kvm-avoid-bogus-vcpu_info-assignment-in-vcpu_registe.patch
## v5.4~97 "xlat: use unsgined type for mount_flags fallback values"
#Patch38: 0038-xlat-use-unsgined-type-for-mount_flags-fallback-valu.patch

## Missing stack traces on attach (https://bugzilla.redhat.com/1788636)
## RHEL 7: https://bugzilla.redhat.com/1790052
## RHEL 8: https://bugzilla.redhat.com/1790053
## RHEL 6 DTS: https://bugzilla.redhat.com/1790058
## RHEL 7 DTS: https://bugzilla.redhat.com/1790057
## RHEL 8 DTS: https://bugzilla.redhat.com/1790054
## v5.4-18-g69b2c33 "unwind-libdw: fix initialization of libdwfl cache"
#Patch39: 0039-unwind-libdw-fix-initialization-of-libdwfl-cache.patch
## v5.4-27-g35e080a "syscall: do not capture stack trace while the tracee executes strace code"
#Patch40: 0040-syscall-do-not-capture-stack-trace-while-the-tracee-.patch
## v5.4-63-g8e515c7 "tests: add strace-k-p test"
#Patch41: 0041-tests-add-strace-k-p-test.patch

## https://bugzilla.redhat.com/1746885
## v5.2-92-gc108f0b "sockaddr: properly decode sockaddr_hci addresses without hci_channel"
#Patch42: 0042-sockaddr-properly-decode-sockaddr_hci-addresses-with.patch

## Some ipc tests from strace internal testsuite occasionally fail
## https://bugzilla.redhat.com/1795251 https://bugzilla.redhat.com/1795261
## https://bugzilla.redhat.com/1794490 https://bugzilla.redhat.com/1795273
## v5.3~102 "tests: fix expected output for some ipc tests"
#Patch43: 0043-tests-fix-expected-output-for-some-ipc-tests.patch
## v5.4~49 "tests: fix -a argument in ipc_msgbuf-Xraw test"
#Patch44: 0044-tests-fix-a-argument-in-ipc_msgbuf-Xraw-test.patch

### Update bpf decoder, as bpf-obj_get_info_by_fd-prog-v.gen.test has started
### to fail after BPF rebase in RHEL 8.2 kernel.
## v5.0~98 "Fix preprocessor indentation", only the bpf_attr.h chunks
#Patch45: 0045-Fix-preprocessor-indentation.patch
## v5.0~24 "bpf: exclude bit fields from the check"
#Patch46: 0046-bpf-exclude-bit-fields-from-the-check.patch
## v5.0~23 "bpf: print struct bpf_prog_info.gpl_compatible"
#Patch47: 0047-bpf-print-struct-bpf_prog_info.gpl_compatible.patch
## v5.0~22 "bpf: add support for btf_* fields in BPF_MAP_CREATE"
#Patch48: 0048-bpf-add-support-for-btf_-fields-in-BPF_MAP_CREATE.patch
## v5.0~21 "bpf: add support for btf_* fields in struct bpf_map_info"
#Patch49: 0049-bpf-add-support-for-btf_-fields-in-struct-bpf_map_in.patch
## v5.0~20 "bpf: add support for *jited_ksyms and *jited_func_lens fields in struct bpf_prog_info"
#Patch50: 0050-bpf-add-support-for-jited_ksyms-and-jited_func_lens-.patch
## v5.0~19 "bpf: add support for new twelve fields in struct bpf_prog_info"
#Patch51: 0051-bpf-add-support-for-new-twelve-fields-in-struct-bpf_.patch
## v5.1~6 "tests: robustify bpf-obj_get_info_by_fd test against future kernels"
#Patch52: 0052-tests-robustify-bpf-obj_get_info_by_fd-test-against-.patch

## Patches 53-86 were on DTS 9 for
## "some devtoolset-9-strace internal tests fail on rhel-alt-7.6"
## https://bugzilla.redhat.com/1758201

## Update io_uring(2) decoder (https://bugzilla.redhat.com/1853011)
## v5.5~65 "io_uring: do not depend on kernel header definitions"
#Patch87:  0087-io_uring-do-not-depend-on-kernel-header-definitions.patch
## v5.5~64 "io_uring: de-indent the switch case statements"
#Patch88:  0088-io_uring-de-indent-the-switch-case-statements.patch
## v5.3~15 "Add support for printing local arrays to print_array"
#Patch89:  0089-Add-support-for-printing-local-arrays-to-print_array.patch
## v5.5~63 "Rework interface for printing local arrays"
#Patch90:  0090-Rework-interface-for-printing-local-arrays.patch
## v5.5~62 "io_uring: decode io_uring_params.resv with IS_ARRAY_ZERO and PRINT_FIELD_ARRAY"
#Patch91:  0091-io_uring-decode-io_uring_params.resv-with-IS_ARRAY_Z.patch
## v5.5~61 "io_uring: print io_sqring_offsets and io_cqring_offsets reserved fields"
#Patch92:  0092-io_uring-print-io_sqring_offsets-and-io_cqring_offse.patch
## v5.5~60 "io_uring: add support for IORING_REGISTER_EVENTFD and IORING_UNREGISTER_EVENTFD"
#Patch93:  0093-io_uring-add-support-for-IORING_REGISTER_EVENTFD-and.patch
## v5.5~59 "io_uring: implement decoding of struct io_uring_params.features"
#Patch94:  0094-io_uring-implement-decoding-of-struct-io_uring_param.patch
## v5.5~58 "xlat: add IORING_SETUP_CQSIZE to uring_setup_flags"
#Patch95:  0095-xlat-add-IORING_SETUP_CQSIZE-to-uring_setup_flags.patch
## v5.5~42 "io_uring: check struct io_* types automatically"
#Patch96:  0096-io_uring-check-struct-io_-types-automatically.patch
## v5.5~41 "io_uring: add support for IORING_REGISTER_FILES_UPDATE"
#Patch97:  0097-io_uring-add-support-for-IORING_REGISTER_FILES_UPDAT.patch
## v5.5~27 "xlat: update uring_setup_features constants"
#Patch98:  0098-xlat-update-uring_setup_features-constants.patch
## v5.5~26 "xlat: add IORING_SETUP_CLAMP to uring_setup_flags"
#Patch99:  0099-xlat-add-IORING_SETUP_CLAMP-to-uring_setup_flags.patch
## v5.5~25 "io_uring: add support of wq_fd field decoding to io_uring_setup"
#Patch100: 0100-io_uring-add-support-of-wq_fd-field-decoding-to-io_u.patch
## v5.6~190 "tests/io_uring_register: properly handle big endian architectures"
#Patch101: 0101-tests-io_uring_register-properly-handle-big-endian-a.patch
## v5.6~157 "io_uring: decode IORING_REGISTER_EVENTFD_ASYNC io_uring_reginster command"
#Patch102: 0102-io_uring-decode-IORING_REGISTER_EVENTFD_ASYNC-io_uri.patch
## v5.6~95 "io_uring: de-indent some code in io_uring_setup decoder"
#Patch103: 0103-io_uring-de-indent-some-code-in-io_uring_setup-decod.patch
## v5.3~29 "defs.h: introduce {opt,dispatch}_{word,klong}size"
#Patch104: 0104-defs.h-introduce-opt-dispatch-_-word-klong-size.patch
## v5.3~9 "Handle xlat verbosity in evdev bitset printing"
#Patch105: 0105-Handle-xlat-verbosity-in-evdev-bitset-printing.patch
## v5.6~94 "io_uring: support IORING_REGISTER_PROBE io_uring_register command"
#Patch106: 0106-io_uring-support-IORING_REGISTER_PROBE-io_uring_regi.patch
## v5.6~93 "io_uring: add support for IORING_{UN,}REGISTER_PERSONALITY commands"
#Patch107: 0107-io_uring-add-support-for-IORING_-UN-REGISTER_PERSONA.patch
## v5.6~17 "tests: fix clang compilation warning"
#Patch108: 0108-tests-fix-clang-compilation-warning.patch
## v5.6~10 "tests: workaround clang compilation warning"
#Patch109: 0109-tests-workaround-clang-compilation-warning.patch
## v5.7~87 "xlat: add IORING_FEAT_FAST_POLL to uring_setup_features"
#Patch110: 0110-xlat-add-IORING_FEAT_FAST_POLL-to-uring_setup_featur.patch
## v5.7~85 "xlat: update uring_ops"
#Patch111: 0111-xlat-update-uring_ops.patch
## v5.7~68 "tests: correct error message in io_uring_register test"
#Patch112: 0112-tests-correct-error-message-in-io_uring_register-tes.patch
## v5.8~58 "io_uring: Remove struct io_cqring_offsets compile time asserts"
#Patch113: 0113-io_uring-Remove-struct-io_cqring_offsets-compile-tim.patch
## v5.8~57 "io_uring: Add io_cqring_offset flags"
#Patch114: 0114-io_uring-Add-io_cqring_offset-flags.patch
## v5.8~47 "xlat: update IORING_* constants"
#Patch115: 0115-xlat-update-IORING_-constants.patch
## v5.5~71 "macros.h: introduce sizeof_field macro"
#Patch116: 0116-macros.h-introduce-sizeof_field-macro.patch
## v5.5~49 "types: new infrastructure for automatic checking of structure types"
#Patch117: 0117-types-new-infrastructure-for-automatic-checking-of-s.patch
## v5.8~59 "types: skip field lines that start with comments"
#Patch118: 0118-types-skip-field-lines-that-start-with-comments.patch

## PID namespace translation support
## https://bugzilla.redhat.com/1035434
## https://bugzilla.redhat.com/1725113 https://bugzilla.redhat.com/1790836
## https://bugzilla.redhat.com/1804334 https://bugzilla.redhat.com/1807458
# v5.8~62 "print_fields.h: add PRINT_FIELD_LEN macro"
#Patch119: 0119-print_fields.h-add-PRINT_FIELD_LEN-macro.patch
## v5.8~61 "Move ilog* functions from util.c to defs.h"
#Patch120: 0120-Move-ilog-functions-from-util.c-to-defs.h.patch
## v5.8~59 "types: skip field lines that start with comments"
#Patch121: 0121-types-skip-field-lines-that-start-with-comments.patch
## v5.8~54 "tests/inject-nf.test: replace getpid with geteuid"
#Patch122: 0122-tests-inject-nf.test-replace-getpid-with-geteuid.patch
## v5.8~18 "fcntl: use print_fields.h macros"
#Patch123: 0123-fcntl-use-print_fields.h-macros.patch
## v5.8~17 "kcmp: fix KCMP_FILE decoding"
#Patch124: 0124-kcmp-fix-KCMP_FILE-decoding.patch
## v5.8~15 "printsiginfo: fix printing of siginfo_t.si_pid and siginfo_t.si_uid"
#Patch125: 0125-printsiginfo-fix-printing-of-siginfo_t.si_pid-and-si.patch
## v5.8~14 "Use PRINT_FIELD_UID instead of printuid where appropriate"
#Patch126: 0126-Use-PRINT_FIELD_UID-instead-of-printuid-where-approp.patch
## v5.8~10 "Consistently print process ids as signed integers"
#Patch127: 0127-Consistently-print-process-ids-as-signed-integers.patch
## v5.8~9 "Remove tcb parameter of read_int_from_file"
#Patch128: 0128-Remove-tcb-parameter-of-read_int_from_file.patch
## v5.8~6 "Add "struct tcb *" parameters to various functions"
#Patch129: 0129-Add-struct-tcb-parameters-to-various-functions.patch
## v5.8~53 "Modify %process class: trace syscalls associated with process lifecycle"
#Patch130: 0130-Modify-process-class-trace-syscalls-associated-with-.patch
## v5.8~5 "Introduce SYS_FUNC(tkill)"
#Patch131: 0131-Introduce-SYS_FUNC-tkill.patch
## v5.8~4 "tests: check decoding of tkill syscall"
#Patch132: 0132-tests-check-decoding-of-tkill-syscall.patch
## v5.8~3 "tests: check decoding of tgkill syscall"
#Patch133: 0133-tests-check-decoding-of-tgkill-syscall.patch
## v5.8-5-gdea0284 "PID namespace translation support"
#Patch134: 0134-PID-namespace-translation-support.patch
## v5.8-6-g173257d "Use printpid in decoders"
#Patch135: 0135-Use-printpid-in-decoders.patch
## v5.8-7-g18c2208 "Use get_proc_pid for /proc paths"
#Patch136: 0136-Use-get_proc_pid-for-proc-paths.patch
## v5.8-8-g7ecee07 "Implement testing framework for pidns"
#Patch137: 0137-Implement-testing-framework-for-pidns.patch
## v5.8-9-gf350ce0 "Add tests for PID namespace translation"
#Patch138: 0138-Add-tests-for-PID-namespace-translation.patch

## v5.12~55 "tests: add fchmod-y test"
#Patch142: 0142-tests-add-fchmod-y-test.patch
## v5.12~54 "tests: introduce create_and_enter_subdir and leave_and_remove_subdir"
#Patch143: 0143-tests-introduce-create_and_enter_subdir-and-leave_an.patch
## v5.8~36 "tests: check decoding of faccessat syscall in -P, -y, and -yy modes"
#Patch144: 0144-tests-check-decoding-of-faccessat-syscall-in-P-y-and.patch
## v5.12~97 "xmalloc: introduce xasprintf"
#Patch145: 0145-xmalloc-introduce-xasprintf.patch
## v5.12~96 "tests: use xasprintf instead of asprintf"
#Patch146: 0146-tests-use-xasprintf-instead-of-asprintf.patch
## v5.12~156 "file_handle: print f_handle as a hexadecimal string"
#Patch147: 0147-file_handle-print-f_handle-as-a-hexadecimal-string.patch
## v5.10~47 "tests: fix execve test with fresh linux kernels"
#Patch148: 0148-tests-fix-execve-test-with-fresh-linux-kernels.patch
## v5.12~49 "Implement --secontext[=full] option to display SELinux contexts"
#Patch149: 0149-Implement-secontext-full-option-to-display-SELinux-c.patch
# v5.13-14-g9623154 "m4/mpers.m4: generate HAVE_*_SELINUX_RUNTIME config defines"
#Patch155: 0155-m4-mpers.m4-generate-HAVE_-_SELINUX_RUNTIME-config-d.patch

## v5.9~28 "Introduce GLIBC_PREREQ_GE and GLIBC_PREREQ_LT macros"
#Patch156: 0156-Introduce-GLIBC_PREREQ_GE-and-GLIBC_PREREQ_LT-macros.patch
## v5.9~27 "tests/ipc_msg.c: disable TEST_MSGCTL_BOGUS_ADDR on glibc >= 2.32"
#Patch157: 0157-tests-ipc_msg.c-disable-TEST_MSGCTL_BOGUS_ADDR-on-gl.patch
## v5.10~46 "tests: disable TEST_MSGCTL_BOGUS_ADDR in ipc_msg test on glibc >= 2.31"
#Patch158: 0158-tests-disable-TEST_MSGCTL_BOGUS_ADDR-in-ipc_msg-test.patch
## v5.10~22 "tests: disable tests for invalid msgctl commands on glibc >= 2.32"
#Patch159: 0159-tests-disable-tests-for-invalid-msgctl-commands-on-g.patch
## v5.9~11 "tests: disable shmctl IPC_STAT test with a bogus address on glibc >= 2.32"
#Patch160: 0160-tests-disable-shmctl-IPC_STAT-test-with-a-bogus-addr.patch
## v5.9~10 "tests: disable tests for invalid shmctl commands on glibc >= 2.32"
#Patch161: 0161-tests-disable-tests-for-invalid-shmctl-commands-on-g.patch
## v5.9~12 "tests: disable tests for invalid semctl commands on glibc >= 2.32"
#Patch162: 0162-tests-disable-tests-for-invalid-semctl-commands-on-g.patch

## v5.13-55-g6b2191f "filter_qualify: free allocated data on the error path exit of parse_poke_token"
#Patch163: 0163-filter_qualify-free-allocated-data-on-the-error-path.patch
## v5.13-56-g80dc60c "macros: expand BIT macros, add MASK macros; add *_SAFE macros"
#Patch164: 0164-macros-expand-BIT-macros-add-MASK-macros-add-_SAFE-m.patch
## v5.13-58-g94ae5c2 "trie: use BIT* and MASK* macros"
#Patch165: 0165-trie-use-BIT-and-MASK-macros.patch
## v5.13-65-g41b753e "tee: rewrite num_params access in tee_fetch_buf_data"
#Patch166: 0166-tee-rewrite-num_params-access-in-tee_fetch_buf_data.patch

## v5.15~1 "print_ifindex: fix IFNAME_QUOTED_SZ definition"
#Patch167: 0167-print_ifindex-fix-IFNAME_QUOTED_SZ-definition.patch

## v5.15~18 "m4: fix st_SELINUX check"
#Patch168: 0168-m4-fix-st_SELINUX-check.patch
## v5.16~31 "Implement displaying of expected context upon mismatch"
#Patch169: 0169-Implement-displaying-of-expected-context-upon-mismat.patch
#Patch170: 0170-tests-linkat-reset-errno-before-SELinux-context-mani.patch
#Patch171: 0171-tests-secontext-add-secontext-field-getters.patch
#Patch172: 0172-tests-linkat-provide-fallback-values-for-secontext-f.patch
#Patch173: 0173-tests-secontext-eliminate-separate-secontext_format-.patch
#Patch174: 0174-tests-linkat-reset-context-to-the-expected-one-if-a-.patch

## https://bugzilla.redhat.com/2103068 covscan fixes
# v5.18-5-g2bf0696 "src/xlat: remove remnants of unnecessary idx usage in xlookup"
Patch175: 0175-src-xlat-remove-remnants-of-unnecessary-idx-usage-in.patch
# v5.18-7-ge604d7b "strauss: tips whitespace and phrasing cleanups"
Patch176: 0176-strauss-tips-whitespace-and-phrasing-cleanups.patch
# v5.18-8-g968789d "strauss: fix off-by-one error in strauss array access"
Patch177: 0177-strauss-fix-off-by-one-error-in-strauss-array-access.patch
# v5.18-9-g6d3e97e "util: add offs sanity check to print_clock_t"
Patch178: 0178-util-add-offs-sanity-check-to-print_clock_t.patch

## https://bugzilla.redhat.com/2087693
# v5.18-13-g960e78f "secontext: print context of Unix socket's sun_path field"
Patch179: 0179-secontext-print-context-of-Unix-socket-s-sun_path-fi.patch
# v5.18-18-g676979f "pathtrace, util: do not print " (deleted)" as part of the path"
Patch180: 0180-pathtrace-util-do-not-print-deleted-as-part-of-the-p.patch
# v5.18-19-g3f0e534 "secontext: fix expected SELinux context check for unlinked FDs"
Patch181: 0181-secontext-fix-expected-SELinux-context-check-for-unl.patch

## https://bugzilla.redhat.com/2103137
# v5.18-21-g5338636 "tests/bpf: fix sloppy low FD number usage"
Patch182: 0182-tests-bpf-fix-sloppy-low-FD-number-usage.patch

### Wire up rseq and kexec_file_load in order to avoid kexec_file_load
### test failure on aarch64. Addresses https://bugzilla.redhat.com/1676045
### ("strace: FTBFS in Fedora rawhide/f30").
## v5.0~62 "Wire up rseq syscall on architectures that use generic unistd.h"
#Patch1000: 1000-Wire-up-rseq-syscall-on-architectures-that-use-gener.patch
## v5.0~61 "Wire up kexec_file_load syscall on architectures that use generic unistd.h"
#Patch1001: 1001-Wire-up-kexec_file_load-syscall-on-architectures-tha.patch

### RHEL7-only: headers on some builders do not provide O_TMPFILE
#Patch2000: 2000-strace-provide-O_TMPFILE-fallback-definition.patch
## RHEL-only: aarch64 brew builders are extremely slow on qual_fault.test
Patch2001: 2001-limit-qual_fault-scope-on-aarch64.patch
### RHEL8.2-only: disable ksysent test due to missing rebase
#Patch2002: 2002-disable-ksysent-on-8.2.patch
### RHEL-only: avoid ARRAY_SIZE macro re-definition in libiberty.h
## No longer needed, since upstream commit v5.14~14
#Patch2003: 2003-undef-ARRAY_SIZE.patch
### RHEL-only: glibc-2.32.9000-147-ga16d2abd496bd974a882,
### glibc-2.32.9000-149-gbe9b0b9a012780a403a2 and
### glibc-2.32.9000-207-g9ebaabeaac1a96b0d91f have been backported in RHEL.
## No longer needed, since upstream commit v5.15~9
#Patch2004: 2004-glibc-msgctl-semctl-shmctl-backport-workaround.patch


# We no longer need to build a separate strace32 binary, but we don't want
# to break existing strace32 users' workflows.
%define strace32_arches ppc64 s390x

%ifarch %{strace32_arches}
%define _isa_compat %{?__isa_name:(%{__isa_name}-32)}%{!?__isa:%{nil}}
%define evr %{?epoch:%{epoch}:}%{version}-%{release}
Provides:  strace32 = %{evr}
# strace32 was a real package before strace-4.24 in RHEL
Obsoletes: strace32 < 4.24
%endif

# Fallback definitions for make_build/make_install macros
%{?!__make:       %global __make %_bindir/make}
%{?!__install:    %global __install %_bindir/install}
%{?!make_build:   %global make_build %__make %{?_smp_mflags}}
%{?!make_install: %global make_install %__make install DESTDIR="%{?buildroot}" INSTALL="%__install -p"}

%description
The strace program intercepts and records the system calls called and
received by a running process.  Strace can print a record of each
system call, its arguments and its return value.  Strace is useful for
diagnosing problems and debugging, as well as for instructional
purposes.

Install strace if you need a tool to track the system calls made and
received by a process.

%prep
%setup -q

#%patch30 -p1
#%patch31 -p1
#%patch32 -p1
#%patch33 -p1
#%patch34 -p1
#%patch35 -p1
#%patch36 -p1
#%patch37 -p1
#%patch38 -p1
#%patch39 -p1
#%patch40 -p1
#%patch41 -p1
#%patch42 -p1
#%patch43 -p1
#%patch44 -p1
#%patch45 -p1
#%patch46 -p1
#%patch47 -p1
#%patch48 -p1
#%patch49 -p1
#%patch50 -p1
#%patch51 -p1
#%patch52 -p1
#%patch87 -p1
#%patch88 -p1
#%patch89 -p1
#%patch90 -p1
#%patch91 -p1
#%patch92 -p1
#%patch93 -p1
#%patch94 -p1
#%patch95 -p1
#%patch96 -p1
#%patch97 -p1
#%patch98 -p1
#%patch99 -p1
#%patch100 -p1
#%patch101 -p1
#%patch102 -p1
#%patch103 -p1
#%patch104 -p1
#%patch105 -p1
#%patch106 -p1
#%patch107 -p1
#%patch108 -p1
#%patch109 -p1
#%patch110 -p1
#%patch111 -p1
#%patch112 -p1
#%patch113 -p1
#%patch114 -p1
#%patch115 -p1
#%patch116 -p1
#%patch117 -p1
#%patch118 -p1
#%patch119 -p1
#%patch120 -p1
#%patch121 -p1
#%patch122 -p1
#%patch123 -p1
#%patch124 -p1
#%patch125 -p1
#%patch126 -p1
#%patch127 -p1
#%patch128 -p1
#%patch129 -p1
#%patch130 -p1
#%patch131 -p1
#%patch132 -p1
#%patch133 -p1
#%patch134 -p1
#%patch135 -p1
#%patch136 -p1
#%patch137 -p1
#%patch138 -p1
#%patch142 -p1
#%patch143 -p1
#%patch144 -p1
#%patch145 -p1
#%patch146 -p1
#%patch147 -p1
#%patch148 -p1
#%patch149 -p1
#%patch155 -p1
#%patch156 -p1
#%patch157 -p1
#%patch158 -p1
#%patch159 -p1
#%patch160 -p1
#%patch161 -p1
#%patch162 -p1
#%patch163 -p1
#%patch164 -p1
#%patch165 -p1
#%patch166 -p1
#%patch167 -p1
#%patch168 -p1
#%patch169 -p1
#%patch170 -p1
#%patch171 -p1
#%patch172 -p1
#%patch173 -p1
#%patch174 -p1

%patch175 -p1
%patch176 -p1
%patch177 -p1
%patch178 -p1
%patch179 -p1
%patch180 -p1
%patch181 -p1
%patch182 -p1

#%patch1000 -p1
#%patch1001 -p1

#%patch2000 -p1
%patch2001 -p1
#%patch2002 -p1
#%patch2003 -p1
#%patch2004 -p1

chmod a+x tests/*.test

echo -n %version-%release > .tarball-version
echo -n 2022 > .year
echo -n 2022-06-22 > doc/.strace.1.in.date
echo -n 2022-06-22 > doc/.strace-log-merge.1.in.date

%build
echo 'BEGIN OF BUILD ENVIRONMENT INFORMATION'
uname -a |head -1
libc="$(ldd /bin/sh |sed -n 's|^[^/]*\(/[^ ]*/libc\.so[^ ]*\).*|\1|p' |head -1)"
$libc |head -1
file -L /bin/sh
gcc --version |head -1
ld --version |head -1
kver="$(printf '%%s\n%%s\n' '#include <linux/version.h>' 'LINUX_VERSION_CODE' | gcc -E -P -)"
printf 'kernel-headers %%s.%%s.%%s\n' $(($kver/65536)) $(($kver/256%%256)) $(($kver%%256))
echo 'END OF BUILD ENVIRONMENT INFORMATION'

CFLAGS=" $RPM_OPT_FLAGS $LDFLAGS "
# Removing explicit -m64 as it breaks mpers
[ "x${CFLAGS#* -m64 }" = "x${CFLAGS}" ] || CFLAGS=$(echo "$CFLAGS" | sed 's/ -m64 / /g')
export CFLAGS

CPPFLAGS=" -isystem %{_includedir} %{optflags} "
# Removing explicit -m64 as it breaks mpers
[ "x${CPPFLAGS#* -m64 }" = "x${CPPFLAGS}" ] || CPPFLAGS=$(echo "$CPPFLAGS" | sed 's/ -m64 / /g')
export CPPFLAGS

CFLAGS_FOR_BUILD="$RPM_OPT_FLAGS"; export CFLAGS_FOR_BUILD
%configure --enable-mpers=check --with-libdw --with-libiberty
%make_build


%install
%make_install

%ifarch %{strace32_arches}
ln -s ./strace %{buildroot}%{_bindir}/strace32
%endif

# remove unpackaged files from the buildroot
rm -f %{buildroot}%{_bindir}/strace-graph

# some say uncompressed changelog files are too big
for f in ChangeLog ChangeLog-CVS; do
        gzip -9n < "$f" > "$f".gz &
done
wait

%check
# This is needed since patch does not set x bit to the newly created files
chmod u+x tests/*.test tests-m32/*.test tests-mx32/*.test

%{buildroot}%{_bindir}/strace -V

# We have to limit concurrent execution of tests as some time-sensitive tests
# start to fail if the reported time is way too off from the expected one.
%make_build -k check VERBOSE=1 V=1
echo 'BEGIN OF TEST SUITE INFORMATION'
tail -n 99999 -- tests*/test-suite.log tests*/ksysent.gen.log
find tests* -type f -name '*.log' -print0 |
	xargs -r0 grep -H '^KERNEL BUG:' -- ||:
echo 'END OF TEST SUITE INFORMATION'

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog.gz ChangeLog-CVS.gz COPYING LGPL-2.1-or-later NEWS README
%{_bindir}/strace
%ifarch %{strace32_arches}
%{_bindir}/strace32
%endif
%{_bindir}/strace-log-merge
%{_mandir}/man1/*

%changelog
* Mon Jul 11 2022 Eugene Syromiatnikov <esyr@redhat.com> - 5.18-2
- Fix the issues reported by covscan (#2103068).
- Fix SELinux context matching for the deleted paths (#2087693).
- Fix sloppy FD usage in the bpf test (#2103137).

* Wed Jun 22 2022 Eugene Syromiatnikov <esyr@redhat.com> - 5.18-1
- Rebase to v5.18; drop upstream patches on top of 5.13 (#2084000).

* Mon Feb 07 2022 Eugene Syromiatnikov <esyr@redhat.com> - 5.13-4
- Update tests-m32 and tests-mx32 with --secontext=mismatch option support
  changes (#2046259).

* Wed Jan 19 2022 Eugene Syromiatnikov <esyr@redhat.com> - 5.13-3
- Add --secontext=mismatch option support (#2038810).

* Wed Jan 05 2022 Eugene Syromiatnikov <esyr@redhat.com> - 5.13-2
- Fix incorrect ifname printing buffer size (#2028158).

* Wed Oct 20 2021 Eugene Syromiatnikov <esyr@redhat.com> - 5.13-1
- Rebase to v5.13; drop upstream patches on top of 5.7 (#2015917).
- Address some issues reported by covscan.

* Mon Aug 09 2021 Eugene Syromiatnikov <esyr@redhat.com> - 5.7-3
- Add SELnux context decoding support (#1946500).

* Mon Nov 09 2020 Eugene Syromiatnikov <esyr@redhat.com> - 5.7-2
- Add PID namespace translation support (#1725113).

* Mon Nov 09 2020 Eugene Syromiatnikov <esyr@redhat.com> - 5.7-1
- Rebase to v5.7; drop upstream patches on top of 5.1 (#1873229).

* Mon Aug 24 2020 Eugene Syromiatnikov <esyr@redhat.com> - 5.1-2
- Update io_uring(2) decoder (#1853011).
- Fix "Obsoletes:" tag on s390x (#1852960).

* Thu Jan 30 2020 Eugene Syromiatnikov <esyr@redhat.com> - 5.1-1
- Rebase to strace 5.1 (#1777847).

* Thu Jan 30 2020 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-9
- Fix the "extra tokens at end of #ifdef directive" warning:
  579f2702 "bpf: exclude bit fields from the check".

* Mon Jan 27 2020 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-8
- Fix expected alignment for IPC tests (#1795251):
  4377e3a1 "tests: fix expected output for some ipc tests", and
  a75c7c4b "tests: fix -a argument in ipc_msgbuf-Xraw test".
- Update tests-m32/looping_threads.test and tests-mx32/looping_threads.test
  in 0025-tests-check-tracing-of-looping-threads.patch.
- Update the bpf syscall decoder:
  d6c71dd0 "Fix preprocessor indentation",
  cabd6955 "bpf: print struct bpf_prog_info.gpl_compatible",
  14a9b6ca "bpf: add support for btf_* fields in BPF_MAP_CREATE",
  27bd13d3 "bpf: add support for btf_* fields in struct bpf_map_info",
  d1f90bcd "bpf: add support for *jited_ksyms and *jited_func_lens fields
           in struct bpf_prog_info", and
  940fe50f "bpf: add support for new twelve fields in struct bpf_prog_info".
  c661605b "tests: robustify bpf-obj_get_info_by_fd test against future kernels"

* Thu Jan 23 2020 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-7
- Fix printing stack traces for early syscalls on process attach (#1790053):
  69b2c33a "unwind-libdw: fix initialization of libdwfl cache" and
  8e515c74 "tests: add strace-k-p test".
- Properly decode struct sockaddr_hci without hci_channel field.
- Update tests-m32/ioctl_evdev.c and tests-mx32/ioctl_evdev.c
  in 0002-evdev-fix-decoding-of-EVIOCGBIT-0.patch.
- Update tests-m32/Makefile.in and tests-mx32/Makefile.in
  in 0032-tests-check-decoding-of-successful-evdev-ioctl.patch.

* Mon Dec 02 2019 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-6
- Pull upstream fix for ioctl evdev bitset decoding, fix the tests (#1747214).
- Include commit v4.26~65 "s390x: beautify sthyi data tail prints" (#1747514).
- Include upstream patches that fix issues reported by covscan (#1747526):
  91281fec "v4l2: avoid shifting left a signed number by 31 bit",
  522ad3a0 "syscall.c: avoid infinite loop in subcalls parsing",
  9446038e "kvm: avoid bogus vcpu_info assignment in vcpu_register", and
  2b64854e "xlat: use unsgined type for mount_flags fallback values".

* Fri Jun 14 2019 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-5
- Use SPDX abbreviations for licenses.

* Wed Jun 12 2019 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-4
- Sync up thread handling unfairness fix with the upstream version.
- Fix "xlat_idx: Unexpected xlat value 0 at index ..." messages (#1660759).
- Remove "ptrace(SYSCALL): No such process" messages (#1662936).
- Wire up rseq and kexec_file_load on aarch64 (#1676045).

* Mon Dec 17 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-3
- Add current version of the thread handling unfairness fix.

* Mon Sep 03 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-2
- Add transition for strace32 package pn those architectures that
  provided it in RHEL 7 (ppc64 and s390x).

* Tue Aug 14 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.24-1
- Rebase to v4.24.

* Sun Aug 05 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.23-4
- Fix tests build with fresh glibc that now provides struct statx in sys/stat.h.
- Resolves #1611749.

* Thu Jul 19 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.23-3
- Wire up io_pgetevents and rseq on hppa, microblaze, mips, powerpc, and s390.

* Sat Jun 16 2018 Eugene Syromiatnikov <esyr@redhat.com> - 4.23-2
- Increase test timeout duration.

* Thu Jun 14 2018 Dmitry V. Levin <ldv@altlinux.org> - 4.23-1
- v4.22 -> v4.23.
- Enabled libdw backend for -k option (#1568647).

* Thu Apr 05 2018 Dmitry V. Levin <ldv@altlinux.org> - 4.22-1
- v4.21 -> v4.22.

* Tue Feb 13 2018 Dmitry V. Levin <ldv@altlinux.org> - 4.21-1
- v4.20 -> v4.21.

* Mon Nov 13 2017 Dmitry V. Levin <ldv@altlinux.org> - 4.20-1
- v4.19 -> v4.20.

* Tue Sep 05 2017 Dmitry V. Levin <ldv@altlinux.org> - 4.19-1
- v4.18 -> v4.19.

* Wed Jul 05 2017 Dmitry V. Levin <ldv@altlinux.org> - 4.18-1
- v4.17 -> v4.18.

* Wed May 24 2017 Dmitry V. Levin <ldv@altlinux.org> - 4.17-1
- v4.16 -> v4.17.

* Tue Feb 14 2017 Dmitry V. Levin <ldv@altlinux.org> - 4.16-1
- v4.15 -> v4.16.

* Wed Dec 14 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.15-1
- v4.14-100-g622af42 -> v4.15.

* Wed Nov 16 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.14.0.100.622a-1
- v4.14 -> v4.14-100-g622af42:
  + implemented syscall fault injection.

* Tue Oct 04 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.14-1
- v4.13 -> v4.14:
  + added printing of the mode argument of open and openat syscalls
    when O_TMPFILE flag is set (#1377846).

* Tue Jul 26 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.13-1
- v4.12 -> v4.13.

* Tue May 31 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.12-1
- v4.11-163-g972018f -> v4.12.

* Fri Feb 05 2016 Fedora Release Engineering <releng@fedoraproject.org> - 4.11.0.163.9720-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Fri Jan 15 2016 Dmitry V. Levin <ldv@altlinux.org> - 4.11.0.163.9720-1
- New upstream snapshot v4.11-163-g972018f:
  + fixed decoding of syscalls unknown to the kernel on s390/s390x (#1298294).

* Wed Dec 23 2015 Dmitry V. Levin <ldv@altlinux.org> - 4.11-2
- Enabled experimental -k option on x86_64 (#1170296).

* Mon Dec 21 2015 Dmitry V. Levin <ldv@altlinux.org> - 4.11-1
- New upstream release:
  + print nanoseconds along with seconds in stat family syscalls (#1251176).

* Fri Jun 19 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.10-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Mon May 11 2015 Marcin Juszkiewicz <mjuszkiewicz@redhat.com> - 4.10-2
- Backport set of upstream patches to get it buildable on AArch64

* Fri Mar 06 2015 Dmitry V. Levin <ldv@altlinux.org> - 4.10-1
- New upstream release:
  + enhanced ioctl decoding (#902788).

* Mon Nov 03 2014 Lubomir Rintel <lkundrak@v3.sk> - 4.9-3
- Regenerate ioctl entries with proper kernel headers

* Mon Aug 18 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Fri Aug 15 2014 Dmitry V. Levin <ldv@altlinux.org> - 4.9-1
- New upstream release:
  + fixed build when <sys/ptrace.h> and <linux/ptrace.h> conflict (#993384);
  + updated CLOCK_* constants (#1088455);
  + enabled ppc64le support (#1122323);
  + fixed attach to a process on ppc64le (#1129569).

* Fri Jul 25 2014 Dan Horák <dan[at]danny.cz> - 4.8-5
- update for ppc64

* Sun Jun 08 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Dec  6 2013 Peter Robinson <pbrobinson@fedoraproject.org> 4.8-3
- Fix FTBFS

* Sun Aug 04 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Mon Jun 03 2013 Dmitry V. Levin <ldv@altlinux.org> - 4.8-1
- New upstream release:
  + fixed ERESTARTNOINTR leaking to userspace on ancient kernels (#659382);
  + fixed decoding of *xattr syscalls (#885233);
  + fixed handling of files with 64-bit inode numbers by 32-bit strace (#912790);
  + added aarch64 support (#969858).

* Fri Feb 15 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.7-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.7-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Wed May 02 2012 Dmitry V. Levin <ldv@altlinux.org> 4.7-1
- New upstream release.
  + implemented proper handling of real SIGTRAPs (#162774).

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Mon Mar 14 2011 Dmitry V. Levin <ldv@altlinux.org> - 4.6-1
- New upstream release.
  + fixed a corner case in waitpid handling (#663547).

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.5.20-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Apr 13 2010 Roland McGrath <roland@redhat.com> - 4.5.20-1
- New upstream release, work mostly by Andreas Schwab and Dmitry V. Levin.
  + fixed potential stack buffer overflow in select decoder (#556678);
  + fixed FTBFS (#539044).

* Wed Oct 21 2009 Roland McGrath <roland@redhat.com> - 4.5.19-1
- New upstream release, work mostly by Dmitry V. Levin <ldv@altlinux.org>
  + exit/kill strace with traced process exitcode/signal (#105371);
  + fixed build on ARM EABI (#507576);
  + fixed display of 32-bit argv array on 64-bit architectures (#519480);
  + fixed display of 32-bit fcntl(F_SETLK) on 64-bit architectures (#471169);
  + fixed several bugs in strings decoder, including potential heap
    memory corruption (#470529, #478324, #511035).

* Thu Aug 28 2008 Roland McGrath <roland@redhat.com> - 4.5.18-1
- build fix for newer kernel headers (#457291)
- fix CLONE_VFORK handling (#455078)
- Support new Linux/PPC system call subpage_prot and PROT_SAO flag.
- In sigaction system call, display sa_flags value along with SIG_DFL/SIG_IGN.

* Mon Jul 21 2008 Roland McGrath <roland@redhat.com> - 4.5.17-1
- handle O_CLOEXEC, MSG_CMSG_CLOEXEC (#365781)
- fix biarch stat64 decoding (#222275)
- fix spurious "..." in printing of environment strings (#358241)
- improve prctl decoding (#364401)
- fix hang wait on exited child with exited child (#354261)
- fix biarch fork/vfork (-f) tracing (#447475)
- fix biarch printing of negative argument kill (#430585)
- fix biarch decoding of error return values (#447587)
- fix -f tracing of CLONE_VFORK (#455078)
- fix ia64 register clobberation in -f tracing (#453438)
- print SO_NODEFER, SA_RESETHAND instead of SA_NOMASK, SA_ONESHOT (#455821)
- fix futex argument decoding (#448628, #448629)

* Fri Aug  3 2007 Roland McGrath <roland@redhat.com> - 4.5.16-1
- fix multithread issues (#240962, #240961, #247907)
- fix spurious SIGSTOP on early interrupt (#240986)
- fix utime for biarch (#247185)
- fix -u error message (#247170)
- better futex syscall printing (##241467)
- fix argv/envp printing with small -s settings, and for biarch
- new syscalls: getcpu, eventfd, timerfd, signalfd, epoll_pwait,
  move_pages, utimensat

* Tue Jan 16 2007 Roland McGrath <roland@redhat.com> - 4.5.15-1
- biarch fixes (#179740, #192193, #171626, #173050, #218433, #218043)
- fix -ff -o behavior (#204950, #218435, #193808, #219423)
- better quotactl printing (#118696)
- *at, inotify*, pselect6, ppoll and unshare syscalls (#178633, #191275)
- glibc-2.5 build fixes (#209856)
- memory corruption fixes (#200621
- fix race in child setup under -f (#180293)
- show ipc key values in hex (#198179, #192182)
- disallow -c with -ff (#187847)
- Resolves: RHBZ #179740, RHBZ #192193, RHBZ #204950, RHBZ #218435
- Resolves: RHBZ #193808, RHBZ #219423, RHBZ #171626, RHBZ #173050
- Resolves: RHBZ #218433, RHBZ #218043, RHBZ #118696, RHBZ #178633
- Resolves: RHBZ #191275, RHBZ #209856, RHBZ #200621, RHBZ #180293
- Resolves: RHBZ #198179, RHBZ #198182, RHBZ #187847

* Mon Nov 20 2006 Jakub Jelinek <jakub@redhat.com> - 4.5.14-4
- Fix ia64 syscall decoding (#206768)
- Fix build with glibc-2.4.90-33 and up on all arches but ia64
- Fix build against 2.6.18+ headers

* Tue Aug 22 2006 Roland McGrath <roland@redhat.com> - 4.5.14-3
- Fix bogus decoding of syscalls >= 300 (#201462, #202620).

* Fri Jul 14 2006 Jesse Keating <jkeating@redhat.com> - 4.5.14-2
- rebuild

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 4.5.14-1.2
- bump again for long double bug on ppc{,64}

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 4.5.14-1.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Mon Jan 16 2006 Roland McGrath <roland@redhat.com> - 4.5.14-1
- Fix biarch decoding of socket syscalls (#174354).
- Fix biarch -e support (#173986).
- Accept numeric syscalls in -e (#174798).
- Fix ipc syscall decoding (#164755).
- Improve msgrcv printing (#164757).
- Man page updates (#165375).
- Improve mount syscall printing (#165377).
- Correct printing of restarting syscalls (#165469).

* Wed Aug  3 2005 Roland McGrath <roland@redhat.com> - 4.5.13-1
- Fix setsockopt decoding on 64-bit (#162449).
- Fix typos in socket option name strings (#161578).
- Display more IPV6 socket options by name (#162450).
- Don't display inappropriate syscalls for -e trace=file (#159340).
- New selector type -e trace=desc for file-descriptor using calls (#159400).
- Fix 32-bit old_mmap syscall decoding on x86-64 (#162467, #164215).
- Fix errors detaching from multithreaded process on interrupt (#161919).
- Note 4.5.12 fix for crash handling bad signal numbers (#162739).

* Wed Jun  8 2005 Roland McGrath <roland@redhat.com> - 4.5.12-1
- Fix known syscall recognition for IA32 processes on x86-64 (#158934).
- Fix bad output for ptrace on x86-64 (#159787).
- Fix potential buffer overruns (#151570, #159196).
- Make some diagnostics more consistent (#159308).
- Update PowerPC system calls.
- Better printing for Linux aio system calls.
- Don't truncate statfs64 fields to 32 bits in output (#158243).
- Cosmetic code cleanups (#159688).

* Tue Mar 22 2005 Roland McGrath <roland@redhat.com> - 4.5.11-1
- Build tweaks.
- Note 4.5.10 select fix (#151570).

* Mon Mar 14 2005 Roland McGrath <roland@redhat.com> - 4.5.10-1
- Fix select handling on nonstandard fd_set sizes.
- Don't print errors for null file name pointers.
- Fix initial execve output with -i (#143365).

* Fri Feb  4 2005 Roland McGrath <roland@redhat.com> - 4.5.9-2
- update ia64 syscall list (#146245)
- fix x86_64 syscall argument extraction for 32-bit processes (#146093)
- fix -e signal=NAME parsing (#143362)
- fix x86_64 exit_group syscall handling
- improve socket ioctl printing (#138223)
- code cleanups (#143369, #143370)
- improve mount flags printing (#141932)
- support symbolic printing of x86_64 arch_prctl parameters (#142667)
- fix potential crash in getxattr printing

* Tue Oct 19 2004 Roland McGrath <roland@redhat.com> - 4.5.8-1
- fix multithreaded exit handling (#132150, #135254)
- fix ioctl name matching (#129808)
- print RTC_* ioctl structure contents (#58606)
- grok epoll_* syscalls (#134463)
- grok new RLIMIT_* values (#133594)
- print struct cmsghdr contents for sendmsg (#131689)
- fix clock_* and timer_* argument output (#131420)

* Tue Aug 31 2004 Roland McGrath <roland@redhat.com> - 4.5.7-2
- new upstream version, misc fixes and updates (#128091, #129166, #128391, #129378, #130965, #131177)

* Mon Jul 12 2004 Roland McGrath <roland@redhat.com> 4.5.6-1
- new upstream version, updates ioctl lists (#127398), fixes quotactl (#127393), more ioctl decoding (#126917)

* Sun Jun 27 2004 Roland McGrath <roland@redhat.com> 4.5.5-1
- new upstream version, fixes x86-64 biarch support (#126547)

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com> 4.5.4-2
- rebuilt

* Thu Jun  3 2004 Roland McGrath <roland@redhat.com> 4.5.4-0.FC1
- rebuilt for FC1 update

* Thu Jun  3 2004 Roland McGrath <roland@redhat.com> 4.5.4-1
- new upstream version, more ioctls (#122257), minor fixes

* Fri Apr 16 2004 Roland McGrath <roland@redhat.com> 4.5.3-1
- new upstream version, mq_* calls (#120701), -p vs NPTL (#120462), more fixes (#118694, #120541, #118685)

* Tue Mar 02 2004 Elliot Lee <sopwith@redhat.com> 4.5.2-1.1
- rebuilt

* Mon Mar  1 2004 Roland McGrath <roland@redhat.com> 4.5.2-1
- new upstream version, sched_* calls (#116990), show core flag (#112117)

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Thu Nov 13 2003 Roland McGrath <roland@redhat.com> 4.5.1-1
- new upstream version, more fixes (#108012, #105366, #105359, #105358)

* Tue Sep 30 2003 Roland McGrath <roland@redhat.com> 4.5-3
- revert bogus s390 fix

* Thu Sep 25 2003 Roland McGrath <roland@redhat.com> 4.5-1.2.1AS
- rebuilt for 2.1AS erratum

* Wed Sep 24 2003 Roland McGrath <roland@redhat.com> 4.5-2
- rebuilt

* Wed Sep 24 2003 Roland McGrath <roland@redhat.com> 4.5-1
- new upstream version, more fixes (#101499, #104365)

* Thu Jul 17 2003 Roland McGrath <roland@redhat.com> 4.4.99-2
- rebuilt

* Thu Jul 17 2003 Roland McGrath <roland@redhat.com> 4.4.99-1
- new upstream version, groks more new system calls, PF_INET6 sockets

* Tue Jun 10 2003 Roland McGrath <roland@redhat.com> 4.4.98-1
- new upstream version, more fixes (#90754, #91085)

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sun Mar 30 2003 Roland McGrath <roland@redhat.com> 4.4.96-1
- new upstream version, handles yet more 2.5 syscalls, x86_64 & ia64 fixes

* Mon Feb 24 2003 Elliot Lee <sopwith@redhat.com> 4.4.95-2
- rebuilt

* Mon Feb 24 2003 Roland McGrath <roland@redhat.com> 4.4.95-1
- new upstream version, fixed getresuid/getresgid (#84959)

* Wed Feb 19 2003 Roland McGrath <roland@redhat.com> 4.4.94-1
- new upstream version, new option -E to set environment variables (#82392)

* Wed Jan 22 2003 Tim Powers <timp@redhat.com> 4.4.93-2
- rebuilt

* Tue Jan 21 2003 Roland McGrath <roland@redhat.com> 4.4.93-1
- new upstream version, fixes ppc and s390 bugs, adds missing ptrace requests

* Fri Jan 10 2003 Roland McGrath <roland@redhat.com> 4.4.91-1
- new upstream version, fixes -f on x86-64

* Fri Jan 10 2003 Roland McGrath <roland@redhat.com> 4.4.90-1
- new upstream version, fixes all known bugs modulo ia64 and s390 issues

* Fri Jan 03 2003 Florian La Roche <Florian.LaRoche@redhat.de> 4.4-11
- add further s390 patch from IBM

* Wed Nov 27 2002 Tim Powers <timp@redhat.com> 4.4-10
- remove unpackaged files from the buildroot

* Mon Oct 07 2002 Phil Knirsch <pknirsch@redhat.com> 4.4-9.1
- Added latest s390(x) patch.

* Fri Sep 06 2002 Karsten Hopp <karsten@redhat.de> 4.4-9
- preliminary x86_64 support with an ugly patch to help
  debugging. Needs cleanup!

* Mon Sep  2 2002 Jakub Jelinek <jakub@redhat.com> 4.4-8
- newer version of the clone fixing patch (Roland McGrath)
- aio syscalls for i386/ia64/ppc (Ben LaHaise)

* Wed Aug 28 2002 Jakub Jelinek <jakub@redhat.com> 4.4-7
- fix strace -f (Roland McGrath, #68994)
- handle ?et_thread_area, SA_RESTORER (Ulrich Drepper)

* Fri Jun 21 2002 Jakub Jelinek <jakub@redhat.com> 4.4-6
- handle futexes, *xattr, sendfile64, etc. (Ulrich Drepper)
- handle modify_ldt (#66894)

* Thu May 23 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Tue Apr 16 2002 Jakub Jelinek <jakub@redhat.com> 4.4-4
- fix for the last patch by Jeff Law (#62591)

* Mon Mar  4 2002 Preston Brown <pbrown@redhat.com> 4.4-3
- integrate patch from Jeff Law to eliminate hang tracing threads

* Sat Feb 23 2002 Florian La Roche <Florian.LaRoche@redhat.de>
- minor update from debian tar-ball

* Wed Jan 02 2002 Florian La Roche <Florian.LaRoche@redhat.de>
- update to 4.4

* Sun Jul 22 2001 Florian La Roche <Florian.LaRoche@redhat.de>
- disable s390 patches, they are already included

* Wed Jul 18 2001 Preston Brown <pbrown@redhat.com> 4.3-1
- new upstream version.  Seems to have integrated most new syscalls
- tracing threaded programs is now functional.

* Mon Jun 11 2001 Than Ngo <than@redhat.com>
- port s390 patches from IBM

* Wed May 16 2001 Nalin Dahyabhai <nalin@redhat.com>
- modify new syscall patch to allocate enough heap space in setgroups32()

* Wed Feb 14 2001 Jakub Jelinek <jakub@redhat.com>
- #include <time.h> in addition to <sys/time.h>

* Fri Jan 26 2001 Karsten Hopp <karsten@redhat.com>
- clean up conflicting patches. This happened only
  when building on S390

* Fri Jan 19 2001 Bill Nottingham <notting@redhat.com>
- update to CVS, reintegrate ia64 support

* Fri Dec  8 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- Get S/390 support into the normal package

* Sat Nov 18 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- added S/390 patch from IBM, adapting it to not conflict with
  IA64 patch

* Sat Aug 19 2000 Jakub Jelinek <jakub@redhat.com>
- doh, actually apply the 2.4 syscalls patch
- make it compile with 2.4.0-test7-pre4+ headers, add
  getdents64 and fcntl64

* Thu Aug  3 2000 Jakub Jelinek <jakub@redhat.com>
- add a bunch of new 2.4 syscalls (#14036)

* Wed Jul 12 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild
- excludearch ia64

* Fri Jun  2 2000 Matt Wilson <msw@redhat.com>
- use buildinstall for FHS

* Wed May 24 2000 Jakub Jelinek <jakub@redhat.com>
- make things compile on sparc
- fix sigreturn on sparc

* Fri Mar 31 2000 Bill Nottingham <notting@redhat.com>
- fix stat64 misdef (#10485)

* Tue Mar 21 2000 Michael K. Johnson <johnsonm@redhat.com>
- added ia64 patch

* Thu Feb 03 2000 Cristian Gafton <gafton@redhat.com>
- man pages are compressed
- version 4.2 (why are we keeping all these patches around?)

* Sat Nov 27 1999 Jeff Johnson <jbj@redhat.com>
- update to 4.1 (with sparc socketcall patch).

* Fri Nov 12 1999 Jakub Jelinek <jakub@redhat.com>
- fix socketcall on sparc.

* Thu Sep 02 1999 Cristian Gafton <gafton@redhat.com>
- fix KERN_SECURELVL compile problem

* Tue Aug 31 1999 Cristian Gafton <gafton@redhat.com>
- added alpha patch from HJLu to fix the osf_sigprocmask interpretation

* Sat Jun 12 1999 Jeff Johnson <jbj@redhat.com>
- update to 3.99.1.

* Wed Jun  2 1999 Jeff Johnson <jbj@redhat.com>
- add (the other :-) jj's sparc patch.

* Wed May 26 1999 Jeff Johnson <jbj@redhat.com>
- upgrade to 3.99 in order to
-    add new 2.2.x open flags (#2955).
-    add new 2.2.x syscalls (#2866).
- strace 3.1 patches carried along for now.

* Sun May 16 1999 Jeff Johnson <jbj@redhat.com>
- don't rely on (broken!) rpm %%patch (#2735)

* Tue Apr 06 1999 Preston Brown <pbrown@redhat.com>
- strip binary

* Sun Mar 21 1999 Cristian Gafton <gafton@redhat.com>
- auto rebuild in the new build environment (release 16)

* Tue Feb  9 1999 Jeff Johnson <jbj@redhat.com>
- vfork est arrive!

* Tue Feb  9 1999 Christopher Blizzard <blizzard@redhat.com>
- Add patch to follow clone() syscalls, too.

* Sun Jan 17 1999 Jeff Johnson <jbj@redhat.com>
- patch to build alpha/sparc with glibc 2.1.

* Thu Dec 03 1998 Cristian Gafton <gafton@redhat.com>
- patch to build on ARM

* Wed Sep 30 1998 Jeff Johnson <jbj@redhat.com>
- fix typo (printf, not tprintf).

* Sat Sep 19 1998 Jeff Johnson <jbj@redhat.com>
- fix compile problem on sparc.

* Tue Aug 18 1998 Cristian Gafton <gafton@redhat.com>
- buildroot

* Mon Jul 20 1998 Cristian Gafton <gafton@redhat.com>
- added the umoven patch from James Youngman <jay@gnu.org>
- fixed build problems on newer glibc releases

* Mon Jun 08 1998 Prospector System <bugs@redhat.com>
- translations modified for de, fr, tr
