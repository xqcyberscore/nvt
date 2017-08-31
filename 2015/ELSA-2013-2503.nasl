# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2503.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123731");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:48 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2503");
script_tag(name: "insight", value: "ELSA-2013-2503 - Unbreakable Enterprise kernel security update - [2.6.39-300.28.1] - kmod: make __request_module() killable (Oleg Nesterov) [Orabug: 16286305] {CVE-2012-4398} - kmod: introduce call_modprobe() helper (Oleg Nesterov) [Orabug: 16286305] {CVE-2012-4398} - usermodehelper: implement UMH_KILLABLE (Oleg Nesterov) [Orabug: 16286305] {CVE-2012-4398} - usermodehelper: introduce umh_complete(sub_info) (Oleg Nesterov) [Orabug: 16286305] {CVE-2012-4398} - KVM: x86: invalid opcode oops on SET_SREGS with OSXSAVE bit set (CVE-2012-4461) (Jerry Snitselaar) [Orabug: 16286290] {CVE-2012-4461} - exec: do not leave bprm->interp on stack (Kees Cook) [Orabug: 16286267] {CVE-2012-4530} - exec: use -ELOOP for max recursion depth (Kees Cook) [Orabug: 16286267] {CVE-2012-4530} [2.6.39-300.27.1] - xen-pciback: rate limit error messages from xen_pcibk_enable_msi{,x}() (Jan Beulich) [Orabug: 16243736] {CVE-2013-0231} - Xen: Fix stack corruption in xen_failsafe_callback for 32bit PVOPS guests. (Frediano Ziglio) [Orabug: 16274171] {CVE-2013-0190} - netback: correct netbk_tx_err to handle wrap around. (Ian Campbell) [Orabug: 16243309] - xen/netback: free already allocated memory on failure in xen_netbk_get_requests (Ian Campbell) [Orabug: 16243309] - xen/netback: don't leak pages on failure in xen_netbk_tx_check_gop. (Ian Campbell) [Orabug: 16243309] - xen/netback: shutdown the ring if it contains garbage. (Ian Campbell) [Orabug: 16243309] - ixgbevf fix typo in Makefile (Maxim Uvarov) [Orabug: 16179639 16168292]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2503");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2503.html");
script_cve_id("CVE-2012-4398","CVE-2012-4461","CVE-2012-4530","CVE-2013-0190","CVE-2013-0231","CVE-2013-0216","CVE-2013-0217");
script_tag(name:"cvss_base", value:"5.2");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~300.28.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~300.28.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

