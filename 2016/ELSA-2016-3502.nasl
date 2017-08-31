# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-3502.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122822");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-01-11 11:11:58 +0200 (Mon, 11 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-3502");
script_tag(name: "insight", value: "ELSA-2016-3502 - Unbreakable Enterprise kernel security update - [2.6.39-400.264.13]- KEYS: Don't permit request_key() to construct a new keyring (David Howells) [Orabug: 22373449] {CVE-2015-7872}[2.6.39-400.264.12]- crypto: add missing crypto module aliases (Mathias Krause) [Orabug: 22249656] {CVE-2013-7421} {CVE-2014-9644}- crypto: include crypto- module prefix in template (Kees Cook) [Orabug: 22249656] {CVE-2013-7421} {CVE-2014-9644}- crypto: prefix module autoloading with 'crypto-' (Kees Cook) [Orabug: 22249656] {CVE-2013-7421} {CVE-2014-9644}[2.6.39-400.264.11]- KVM: x86: Don't report guest userspace emulation error to userspace (Nadav Amit) [Orabug: 22249615] {CVE-2010-5313} {CVE-2014-7842}[2.6.39-400.264.9]- msg_unlock() in wrong spot after applying 'Initialize msg/shm IPC objects before doing ipc_addid()' (Chuck Anderson) [Orabug: 22250044] {CVE-2015-7613} {CVE-2015-7613}[2.6.39-400.264.8]- ipc/sem.c: fully initialize sem_array before making it visible (Manfred Spraul) [Orabug: 22250044] {CVE-2015-7613}- Initialize msg/shm IPC objects before doing ipc_addid() (Linus Torvalds) [Orabug: 22250044] {CVE-2015-7613}[2.6.39-400.264.7]- KVM: svm: unconditionally intercept #DB (Paolo Bonzini) [Orabug: 22333698] {CVE-2015-8104} {CVE-2015-8104}- KVM: x86: work around infinite loop in microcode when #AC is delivered (Eric Northup) [Orabug: 22333689] {CVE-2015-5307} {CVE-2015-5307}[2.6.39-400.264.6]- mlx4_core: Introduce restrictions for PD update (Ajaykumar Hotchandani) - IPoIB: Drop priv->lock before calling ipoib_send() (Wengang Wang) - IPoIB: serialize changing on tx_outstanding (Wengang Wang) [Orabug: 21861366] - IB/mlx4: Implement IB_QP_CREATE_USE_GFP_NOIO (Jiri Kosina) - IB: Add a QP creation flag to use GFP_NOIO allocations (Or Gerlitz) - IB: Return error for unsupported QP creation flags (Or Gerlitz) - IB/ipoib: Calculate csum only when skb->ip_summed is CHECKSUM_PARTIAL (Yuval Shaia) [Orabug: 20873175]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-3502");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-3502.html");
script_cve_id("CVE-2013-7421","CVE-2014-9644","CVE-2014-7842","CVE-2015-7613","CVE-2015-5307","CVE-2015-8104");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.264.13.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.264.13.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

