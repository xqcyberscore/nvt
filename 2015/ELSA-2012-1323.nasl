# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1323.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123808");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:50 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1323");
script_tag(name: "insight", value: "ELSA-2012-1323 -  kernel security and bug fix update - kernel[2.6.18-308.16.1.el5]- Revert: [fs] nfsd4: Remove check for a 32-bit cookie in nfsd4_readdir() (Eric Sandeen) [847943 784191]- Revert: [fs] add new FMODE flags: FMODE_32bithash and FMODE_64bithash (Eric Sandeen) [847943 784191]- Revert: [fs] nfsd: rename int access to int may_flags in nfsd_open() (Eric Sandeen) [847943 784191]- Revert: [fs] nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes) (Eric Sandeen) [847943 784191]- Revert: [fs] vfs: add generic_file_llseek_size (Eric Sandeen) [847943 784191]- Revert: [s390/ppc64] add is_compat_task() for s390 and ppc64 (Eric Sandeen) [847943 784191]- Revert: [fs] ext3: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]- Revert: [fs] ext4: improve llseek error handling for large seek offsets (Eric Sandeen) [847943 784191]- Revert: [fs] ext4: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]- Revert: [fs] vfs: allow custom EOF in generic_file_llseek code (Eric Sandeen) [847943 784191]- Revert: [fs] ext4: use core vfs llseek code for dir seeks (Eric Sandeen) [847943 784191]- Revert: [fs] ext3: pass custom EOF to generic_file_llseek_size() (Eric Sandeen) [847943 784191][2.6.18-308.15.1.el5]- [net] sfc: Fix max no of TSO segments and min TX queue size (Michal Schmidt) [845554 845555] {CVE-2012-3412}- [kernel] xacct_add_tsk: fix pure theoretical ->mm use-after-free (Nikola Pajkovsky) [849723 849725] {CVE-2012-3510}- [fs] hfsplus: Buffer overflow in the HFS plus filesystem (Jacob Tanenbaum) [820255 820256] {CVE-2012-2319}- [net] netfilter: add dscp netfilter match (Thomas Graf) [847327 842029]- [net] rds: set correct msg_namelen (Weiping Pan) [822727 822728] {CVE-2012-3430}- [misc] ERESTARTNOINTR seen from fork call in userspace (Oleg Nesterov) [847359 693822]- [fs] quota: manage reserved space when quota is not active (Eric Sandeen) [847326 818087]- [fs] quota: Fix warning if delayed write before quota is enabled (Eric Sandeen) [847326 818087]- [fs] ext3: pass custom EOF to generic_file_llseek_size() (Eric Sandeen) [847943 784191]- [fs] ext4: use core vfs llseek code for dir seeks (Eric Sandeen) [847943 784191]- [fs] vfs: allow custom EOF in generic_file_llseek code (Eric Sandeen) [847943 784191]- [fs] ext4: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]- [fs] ext4: improve llseek error handling for large seek offsets (Eric Sandeen) [847943 784191]- [fs] ext3: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]- [s390/ppc64] add is_compat_task() for s390 and ppc64 (Eric Sandeen) [847943 784191]- [fs] vfs: add generic_file_llseek_size (Eric Sandeen) [847943 784191]- [fs] nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes) (Eric Sandeen) [847943 784191]- [fs] nfsd: rename int access to int may_flags in nfsd_open() (Eric Sandeen) [847943 784191]- [fs] add new FMODE flags: FMODE_32bithash and FMODE_64bithash (Eric Sandeen) [847943 784191]- [fs] nfsd4: Remove check for a 32-bit cookie in nfsd4_readdir() (Eric Sandeen) [847943 784191]- [xen] x86: whitelist Enhanced SpeedStep for dom0 (Laszlo Ersek) [846125 809103][2.6.18-308.14.1.el5]- [net] e1000e: drop check of RXCW.CW to eliminate link up and down (Dean Nelson) [852448 840642]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1323");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1323.html");
script_cve_id("CVE-2012-3430","CVE-2012-2319","CVE-2012-3412","CVE-2012-3510");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.16.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.16.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.16.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.16.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.16.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.16.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.16.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.16.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

