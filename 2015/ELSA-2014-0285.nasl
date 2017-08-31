# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0285.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123451");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:03:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0285");
script_tag(name: "insight", value: "ELSA-2014-0285 -  kernel security, bug fix, and enhancement update - kernel[2.6.18-371.6.1]- [net] be2net: don't use skb_get_queue_mapping() (Ivan Vecera) [1066302 1063955]- [ipc] change refcount to atomic_t (Phillip Lougher) [1024866 1024868] {CVE-2013-4483}- [s390] qeth: buffer overflow in snmp ioctl (Jacob Tanenbaum) [1034402 1034404] {CVE-2013-6381}- [scsi] AACRAID Driver compat IOCTL missing capability check (Jacob Tanenbaum) [1033531 1033532] {CVE-2013-6383}- [xen] x86/AMD: work around erratum 793 (Radim Krcmar) [1035834 1035836] {CVE-2013-6885}- [xen] do not expose hypercalls to rings 1 and 2 of HVM guests (Andrew Jones) [1029112 1029113] {CVE-2013-4554}- [redhat] kabi: Adding symbol print_hex_dump (Jiri Olsa) [1054055 662558]- [scsi] Add 'eh_deadline' to limit SCSI EH runtime (Ewan Milne) [1050097 956132]- [scsi] remove check for 'resetting' (Ewan Milne) [1050097 956132]- [scsi] dc395: Move 'last_reset' into internal host structure (Ewan Milne) [1050097 956132]- [scsi] tmscsim: Move 'last_reset' into host structure (Ewan Milne) [1050097 956132]- [scsi] advansys: Remove 'last_reset' references (Ewan Milne) [1050097 956132]- [scsi] dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset (Ewan Milne) [1050097 956132]- [scsi] dpt_i2o: Remove DPTI_STATE_IOCTL (Ewan Milne) [1050097 956132]- [net] ipv6: fix leaking uninit port number of offender sockaddr (Florian Westphal) [1035880 1035881] {CVE-2013-7264 CVE-2013-7265 CVE-2013-7281 CVE-2013-7263}- [net] fix addr_len/msg->msg_namelen assign in recv_error funcs (Florian Westphal) [1035880 1035881] {CVE-2013-7264 CVE-2013-7265 CVE-2013-7281 CVE-2013-7263}- [net] prevent leakage of uninitialized memory to user in recv (Florian Westphal) [1035880 1035881] {CVE-2013-7264 CVE-2013-7265 CVE-2013-7281 CVE-2013-7263}- [net] be2net: prevent Tx stall on SH-R when packet size < 32 (Ivan Vecera) [1051535 1007995]- [net] be2net: Trim padded packets for Lancer (Ivan Vecera) [1051535 1007995]- [net] be2net: Pad skb to meet min Tx pkt size in lancer (Ivan Vecera) [1051535 1007995]- [net] be2net: refactor HW workarounds in be_xmit() (Ivan Vecera) [1051535 1007995]- [fs] exec/ptrace: fix get_dumpable() incorrect tests (Petr Oros) [1039483 1039484] {CVE-2013-2929}[2.6.18-371.5.1]- [fs] cifs: stop trying to use virtual circuits (Sachin Prabhu) [1044328 1013469]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0285");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0285.html");
script_cve_id("CVE-2013-4554","CVE-2013-2929","CVE-2013-6381","CVE-2013-7263","CVE-2013-4483","CVE-2013-6383","CVE-2013-6885");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.6.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.6.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.6.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.6.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.6.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.6.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.6.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.6.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.6.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

