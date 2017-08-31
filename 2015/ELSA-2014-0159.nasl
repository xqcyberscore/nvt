# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0159.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123469");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:13 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0159");
script_tag(name: "insight", value: "ELSA-2014-0159 -  kernel security and bug fix update - [2.6.32-431.5.1]- [net] sctp: fix checksum marking for outgoing packets (Daniel Borkmann) [1046041 1040385]- [kernel] ptrace: Cleanup useless header (Aaron Tomlin) [1046043 1036312]- [kernel] ptrace: kill BKL in ptrace syscall (Aaron Tomlin) [1046043 1036312]- [fs] nfs: Prevent a 3-way deadlock between layoutreturn, open and state recovery (Steve Dickson) [1045094 1034487]- [fs] nfs: Ensure that rmdir() waits for sillyrenames to complete (Steve Dickson) [1051395 1034348]- [fs] nfs: wait on recovery for async session errors (Steve Dickson) [1051393 1030049]- [fs] nfs: Re-use exit code in nfs4_async_handle_error() (Steve Dickson) [1051393 1030049]- [fs] nfs: Update list of irrecoverable errors on DELEGRETURN (Steve Dickson) [1051393 1030049]- [exec] ptrace: fix get_dumpable() incorrect tests (Petr Oros) [1039486 1039487] {CVE-2013-2929}- [net] ipv6: router reachability probing (Jiri Benc) [1043779 1029585]- [net] ipv6: remove the unnecessary statement in find_match() (Jiri Benc) [1043779 1029585]- [net] ipv6: fix route selection if kernel is not compiled with CONFIG_IPV6_ROUTER_PREF (Jiri Benc) [1043779 1029585]- [net] ipv6: Fix default route failover when CONFIG_IPV6_ROUTER_PREF=n (Jiri Benc) [1043779 1029585]- [net] ipv6: probe routes asynchronous in rt6_probe (Jiri Benc) [1040826 1030094]- [net] ndisc: Update neigh->updated with write lock (Jiri Benc) [1040826 1030094]- [net] ipv6: prevent fib6_run_gc() contention (Jiri Benc) [1040826 1030094]- [net] netfilter: push reasm skb through instead of original frag skbs (Jiri Pirko) [1049590 1011214]- [net] ip6_output: fragment outgoing reassembled skb properly (Jiri Pirko) [1049590 1011214]- [net] netfilter: nf_conntrack_ipv6: improve fragmentation handling (Jiri Pirko) [1049590 1011214]- [net] ipv4: fix path MTU discovery with connection tracking (Jiri Pirko) [1049590 1011214]- [net] ipv6: Make IP6CB(skb)->nhoff 16-bit (Jiri Pirko) [1049590 1011214]- [edac] Add error decoding support for AMD Fam16h processors (Prarit Bhargava) [1051394 1020290]- [netdrv] bnx2x: correct VF-PF channel locking scheme (Michal Schmidt) [1040498 1029203]- [netdrv] bnx2x: handle known but unsupported VF messages (Michal Schmidt) [1040498 1029203]- [netdrv] bnx2x: Lock DMAE when used by statistic flow (Michal Schmidt) [1040497 1029200]- [net] ipv6: fix leaking uninitialized port number of offender sockaddr (Florian Westphal) [1035882 1035883] {CVE-2013-6405}- [net] inet: fix addr_len/msg->msg_namelen assignment in recv_error functions (Florian Westphal) [1035882 1035883] {CVE-2013-6405}- [net] inet: prevent leakage of uninitialized memory to user in recv syscalls (Florian Westphal) [1035882 1035883] {CVE-2013-6405}- [net] ipvs: Add boundary check on ioctl arguments (Denys Vlasenko) [1030817 1030818] {CVE-2013-4588}- [s390] qeth: avoid buffer overflow in snmp ioctl (Hendrik Brueckner) [1038935 1034266]- [md] fix calculation of stacking limits on level change (Jes Sorensen) [1035347 1026864]- [ata] ahci: fix turning on LEDs in ahci_start_port() (David Milburn) [1035339 1017105]- [ata] libata: implement cross-port EH exclusion (David Milburn) [1035339 1017105]- [ata] libata add ap to ata_wait_register and intro ata_msleep (David Milburn) [1035339 1017105]- [netdrv] igb: Update link modes display in ethtool (Stefan Assmann) [1032389 1019578][2.6.32-431.4.1]- [powerpc] signals: Improved mark VSX not saved with small contexts fix (Seth Jennings) [1044566 1044117]- [powerpc] signals: Mark VSX not saved with small contexts (Seth Jennings) [1044566 1044117]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0159");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0159.html");
script_cve_id("CVE-2013-2929","CVE-2013-6381","CVE-2013-7263","CVE-2013-7265");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

