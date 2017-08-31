# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0102.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123194");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:33 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0102");
script_tag(name: "insight", value: "ELSA-2015-0102 -  kernel security and bug fix update - [3.10.0-123.20.1]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-123.20.1]- [fs] seq_file: don't include mm.h in genksyms calculation (Ian Kent) [1184152 1183280][3.10.0-123.19.1]- [mm] shmem: fix splicing from a hole while it's punched (Denys Vlasenko) [1118244 1118245] {CVE-2014-4171}- [mm] shmem: fix faulting into a hole, not taking i_mutex (Denys Vlasenko) [1118244 1118245] {CVE-2014-4171}- [mm] shmem: fix faulting into a hole while it's punched (Denys Vlasenko) [118244 1118245] {CVE-2014-4171}- [x86] traps: stop using IST for #SS (Petr Matousek) [1172812 1172813] {CVE-2014-9322}- [net] vxlan: fix incorrect initializer in union vxlan_addr (Daniel Borkmann) [1156611 1130643]- [net] vxlan: fix crash when interface is created with no group (Daniel Borkmann) [1156611 1130643]- [net] vxlan: fix nonfunctional neigh_reduce() (Daniel Borkmann) [1156611 1130643]- [net] vxlan: fix potential NULL dereference in arp_reduce() (Daniel Borkmann) [1156611 1130643]- [net] vxlan: remove unused port variable in vxlan_udp_encap_recv() (Daniel Borkmann) [1156611 1130643]- [net] vxlan: remove extra newline after function definition (Daniel Borkmann) [1156611 1130643]- [net] etherdevice: Use ether_addr_copy to copy an Ethernet address (Stefan Assmann) [1156611 1091126]- [fs] splice: perform generic write checks (Eric Sandeen) [1163799 1155907] {CVE-2014-7822}- [fs] eliminate BUG() call when there's an unexpected lock on file close (Frank Sorenson) [1172266 1148130]- [net] sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet (Daniel Borkmann) [1163094 1154002] {CVE-2014-7841}- [fs] lockd: Try to reconnect if statd has moved (Benjamin Coddington) [1150889 1120850]- [fs] sunrpc: Don't wake tasks during connection abort (Benjamin Coddington) [1150889 1120850]- [fs] cifs: NULL pointer dereference in SMB2_tcon (Jacob Tanenbaum) [1147528 1147529] {CVE-2014-7145}- [net] ipv6: addrconf: implement address generation modes (Jiri Pirko) [1144876 1107369]- [net] gre: add link local route when local addr is any (Jiri Pirko) [1144876 1107369]- [net] gre6: don't try to add the same route two times (Jiri Pirko) [1144876 1107369]- [fs] isofs: unbound recursion when processing relocated directories (Jacob Tanenbaum) [1142270 1142271] {CVE-2014-5471 CVE-2014-5472}- [fs] fs: seq_file: fallback to vmalloc allocation (Ian Kent) [1140302 1095623]- [fs] fs: /proc/stat: convert to single_open_size() (Ian Kent) [1140302 1095623]- [fs] fs: seq_file: always clear m->count when we free m->buf (Ian Kent) [1140302 1095623][3.10.0-123.18.1]- [net] ipv6: fib: fix fib dump restart (Panu Matilainen) [1172795 1163605]- [net] ipv6: drop unused fib6_clean_all_ro() function and rt6_proc_arg struct (Panu Matilainen) [1172795 1163605]- [net] ipv6: avoid high order memory allocations for /proc/net/ipv6_route (Panu Matilainen) [1172795 1163605]- [mm] numa: Remove BUG_ON() in __handle_mm_fault() (Rik van Riel) [1170662 1119439]- [fs] aio: fix race between aio event completion and reaping (Jeff Moyer) [1154172 1131312][3.10.0-123.17.1]- [ethernet] mlx4: Protect port type setting by mutex (Amir Vadai) [1162733 1095345][3.10.0-123.16.1]- [fs] aio: block exit_aio() until all context requests are completed (Jeff Moyer) [1163992 1122092]- [fs] aio: add missing smp_rmb() in read_events_ring (Jeff Moyer) [1154172 1131312]- [fs] aio: fix reqs_available handling (Jeff Moyer) [1163992 1122092]- [fs] aio: report error from io_destroy() when threads race in io_destroy() (Jeff Moyer) [1163992 1122092]- [fs] aio: block io_destroy() until all context requests are completed (Jeff Moyer) [1163992 1122092]- [fs] aio: v4 ensure access to ctx->ring_pages is correctly serialised for migration (Jeff Moyer) [1163992 1122092]- [fs] aio/migratepages: make aio migrate pages sane (Jeff Moyer) [1163992 1122092]- [fs] aio: clean up and fix aio_setup_ring page mapping (Jeff Moyer) [1163992 1122092][3.10.0-123.15.1]- [scsi] ipr: wait for aborted command responses (Gustavo Duarte) [1162734 1156530]- [scsi] reintroduce scsi_driver.init_command (Ewan Milne) [1146983 1105204]- [block] implement an unprep function corresponding directly to prep (Ewan Milne) [1146983 1105204]- [scsi] Revert: reintroduce scsi_driver.init_command (Ewan Milne) [1146983 1105204][3.10.0-123.14.1]- [fs] nfs: Fix another nfs4_sequence corruptor (Steve Dickson) [1162073 1111170]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0102");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0102.html");
script_cve_id("CVE-2014-4171","CVE-2014-5471","CVE-2014-5472","CVE-2014-7841","CVE-2014-7145","CVE-2014-7822");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

