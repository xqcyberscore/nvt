# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1292.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123567");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:37 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1292");
script_tag(name: "insight", value: "ELSA-2013-1292 -  kernel security and bug fix update - kernel[2.6.18-348.18.1]- [net] be2net: enable polling prior enabling interrupts globally (Ivan Vecera) [1005239 987539]- [kernel] signals: stop info leak via tkill and tgkill syscalls (Oleg Nesterov) [970874 970875] {CVE-2013-2141}- [net] ipv6: do udp_push_pending_frames AF_INET sock pending data (Jiri Benc) [987647 987648] {CVE-2013-4162}- [mm] use-after-free in madvise_remove() (Jacob Tanenbaum) [849735 849736] {CVE-2012-3511}- [fs] autofs: remove autofs dentry mount check (Ian Kent) [1001488 928098][2.6.18-348.17.1]- [net] be2net: Fix to avoid hardware workaround when not needed (Ivan Vecera) [999819 995961]- [net] be2net: Mark checksum fail for IP fragmented packets (Ivan Vecera) [983864 956322]- [net] be2net: Avoid double insertion of vlan tags (Ivan Vecera) [983864 956322]- [net] be2net: disable TX in be_close() (Ivan Vecera) [983864 956322]- [net] be2net: fix EQ from getting full while cleaning RX CQ (Ivan Vecera) [983864 956322]- [net] be2net: avoid napi_disable() when not enabled (Ivan Vecera) [983864 956322]- [net] be2net: Fix receive Multicast Packets w/ Promiscuous mode (Ivan Vecera) [983864 956322]- [net] be2net: Fixed memory leak (Ivan Vecera) [983864 956322]- [net] be2net: Fix PVID tag offload for packets w/ inline VLAN tag (Ivan Vecera) [983864 956322]- [net] be2net: fix a Tx stall bug caused by a specific ipv6 packet (Ivan Vecera) [983864 956322]- [net] be2net: Remove an incorrect pvid check in Tx (Ivan Vecera) [983864 956322]- [net] be2net: Fix issues in error recovery with wrong queue state (Ivan Vecera) [983864 956322]- [net] netpoll: revert 6bdb7fe3104 and fix be_poll() instead (Ivan Vecera) [983864 956322]- [net] be2net: Fix to parse RSS hash Receive completions correctly (Ivan Vecera) [983864 956322]- [net] be2net: Fix cleanup path when EQ creation fails (Ivan Vecera) [983864 956322]- [net] be2net: Fix Endian (Ivan Vecera) [983864 956322]- [net] be2net: Fix to trim skb for padded vlan packets (Ivan Vecera) [983864 956322]- [net] be2net: Explicitly clear reserved field in Tx Descriptor (Ivan Vecera) [983864 956322]- [net] be2net: remove unnecessary usage of unlikely() (Ivan Vecera) [983864 956322]- [net] be2net: do not modify PCI MaxReadReq size (Ivan Vecera) [983864 956322]- [net] be2net: cleanup be_vid_config() (Ivan Vecera) [983864 956322]- [net] be2net: don't call vid_config() when there no vlan config (Ivan Vecera) [983864 956322]- [net] be2net: Ignore status of some ioctls during driver load (Ivan Vecera) [983864 956322]- [net] be2net: Fix wrong status getting returned for MCC commands (Ivan Vecera) [983864 956322]- [net] be2net: Fix VLAN/multicast packet reception (Ivan Vecera) [983864 956322]- [net] be2net: fix wrong frag_idx reported by RX CQ (Ivan Vecera) [983864 956322]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1292");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1292.html");
script_cve_id("CVE-2012-3511","CVE-2013-2141","CVE-2013-4162");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.18.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.18.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.18.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.18.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.18.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.18.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.18.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.18.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

