# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1436.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.123553");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:27 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1436");
script_tag(name: "insight", value: "ELSA-2013-1436 -  kernel security and bug fix update - [2.6.32-358.23.2]- [md] dm-snapshot: fix data corruption (Mikulas Patocka) [1004252 1004233] {CVE-2013-4299}[2.6.32-358.23.1]- [md] raid1, raid10: use freeze_array in place of raise_barrier in various places (Jes Sorensen) [1003765 997845]- [scsi] megaraid_sas: megaraid_sas driver init fails in kdump kernel (Nikola Pajkovsky) [1001963 833299]- [char] ipmi: eliminate long delay in ipmi_si on SGI UV2 (Nikola Pajkovsky) [988228 876778]- [net] bridge: Add multicast_querier toggle and disable queries by default (Nikola Pajkovsky) [995334 905561]- [net] bridge: Fix fatal typo in setup of multicast_querier_expired (Nikola Pajkovsky) [995334 905561]- [net] bridge: Restart queries when last querier expires (Nikola Pajkovsky) [995334 905561]- [net] bridge: Add br_multicast_start_querier (Flavio Leitner) [995334 905561]- [kernel] Prevent RT process stall due to missing upstream scheduler bug fix (Larry Woodman) [1006932 1002765]- [fs] nfs: Minor cleanups for nfs4_handle_exception and nfs4_async_handle_error (Dave Wysochanski) [1006956 998752]- [firmware] efivars: Use correct efi_pstore_info struct when calling pstore_register (Lenny Szubowicz) [993547 867689]- [net] bridge: do not call setup_timer() multiple times (Amerigo Wang) [997746 994430]- [fs] lockd: protect nlm_blocked list (David Jeffery) [993544 967095]- [net] ipv6: call udp_push_pending_frames when uncorking a socket with AF_INET pending data (Jiri Benc) [987649 987651] {CVE-2013-4162}- [fs] fuse: readdirplus sanity checks (Niels de Vos) [988708 981741]- [fs] fuse: readdirplus cleanup (Niels de Vos) [988708 981741]- [fs] fuse: readdirplus change attributes once (Niels de Vos) [988708 981741]- [fs] fuse: readdirplus fix instantiate (Niels de Vos) [988708 981741]- [fs] fuse: fix readdirplus dentry leak (Niels de Vos) [988708 981741]- [fs] cifs: fix issue mounting of DFS ROOT when redirecting from one domain controller to the next (Sachin Prabhu) [994866 976535]- [fs] nfs: Make nfs_readdir revalidate less often (Scott Mayhew) [994867 976879]- [fs] nfs: Make nfs_attribute_cache_expired() non-static (Scott Mayhew) [994867 976879]- [fs] nfs: set verifier on existing dentries in nfs_prime_dcache (Scott Mayhew) [994867 976879]- [fs] nfs: Allow nfs_updatepage to extend a write under additional circumstances (Scott Mayhew) [987262 983288]- [fs] nfs: fix a leak at nfs_lookup_revalidate() (Dave Wysochanski) [987261 975211]- [acpi] efivars: If pstore_register fails, free unneeded pstore buffer (Lenny Szubowicz) [993547 867689]- [acpi] Eliminate console msg if pstore.backend excludes ERST (Lenny Szubowicz) [993547 867689]- [acpi] Return unique error if backend registration excluded by kernel param (Lenny Szubowicz) [993547 867689]- [net] bridge: fix some kernel warning in multicast timer (Amerigo Wang) [997745 952012]- [net] bridge: send query as soon as leave is received (Amerigo Wang) [997745 952012]- [net] bridge: only expire the mdb entry when query is received (Amerigo Wang) [997745 952012]- [net] bridge: Replace mp->mglist hlist with a bool (Amerigo Wang) [997745 952012]- [mm] fadvise: drain all pagevecs if POSIX_FADV_DONTNEED fails to discard all pages (Larry Woodman) [994140 957821]- [net] sunrpc: don't use a credential with extra groups (Mateusz Guzik) [1003931 955712]- [virt] xen-netfront: reduce gso_max_size to account for max TCP header (Andrew Jones) [1004657 957231]- [pps] Fix a use-after free bug when unregistering a source (Jiri Benc) [997916 920155]- [scsi] fnic: Fix SGEs limit (Chris Leech) [991346 829506][2.6.32-358.22.1]- [x86] Round the calculated scale factor in set_cyc2ns_scale() (Prarit Bhargava) [1001954 975507]- [x86] sched: Fix overflow in cyc2ns_offset (Prarit Bhargava) [1001954 975507][2.6.32-358.21.1]- [fs] autofs: remove autofs dentry mount check (Ian Kent) [1000314 947275]- [net] sctp: Fix list corruption resulting from freeing an association on a list (Jiri Pirko) [1002184 887868][2.6.32-358.20.1]- [fs] nfs: Add functionality to allow waiting on all outstanding reads to complete (Dave Wysochanski) [996424 976915]- [fs] nfs: Ensure that NFS file unlock waits for readahead to complete (Dave Wysochanski) [996424 976915]- [fs] nfs: Convert nfs_get_lock_context to return an ERR_PTR on failure (Dave Wysochanski) [996424 976915]- [x86] thermal: Disable power limit notification interrupt (Shyam Iyer) [999328 908990]- [x86] thermal: Delete power-limit-notification console messages (Shyam Iyer) [999328 908990][2.6.32-358.19.1]- [fs] gfs2: Reserve journal space for quota change in do_grow (Robert S Peterson) [988384 976823]- [netdrv] bonding: properly unset current_arp_slave on slave link up (Veaceslav Falico) [995458 988460]- [fs] nfs4: Fix infinite loop in nfs4_lookup_root (Scott Mayhew) [996014 987426]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1436");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1436.html");
script_cve_id("CVE-2013-4162","CVE-2013-4299");
script_tag(name:"cvss_base", value:"6.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.23.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

