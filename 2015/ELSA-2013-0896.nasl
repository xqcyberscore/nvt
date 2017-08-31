# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0896.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123614");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:18 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0896");
script_tag(name: "insight", value: "ELSA-2013-0896 -  qemu-kvm security and bug fix update - [0.12.1.2-2.355.el6_4.5]- kvm-e1000-fix-link-down-handling-with-auto-negotiation.patch [bz#907716]- kvm-e1000-unbreak-the-guest-network-when-migration-to-RH.patch [bz#907716]- kvm-reimplement-error_setg-and-error_setg_errno-for-RHEL.patch [bz#957056]- kvm-qga-set-umask-0077-when-daemonizing-CVE-2013-2007.patch [bz#957056]- kvm-qga-distinguish-binary-modes-in-guest_file_open_mode.patch [bz#957056]- kvm-qga-unlink-just-created-guest-file-if-fchmod-or-fdop.patch [bz#957056]- Resolves: bz#907716 (use set_link to change rtl8139 and e1000 network card's status but fail to make effectively after reboot guest)- Resolves: bz#957056 (CVE-2013-2007 qemu: guest agent creates files with insecure permissions in deamon mode [rhel-6.4.z])[0.12.1.2-2.355.el6_4.4]- kvm-virtio-balloon-fix-integer-overflow-in-BALLOON_CHANG.patch [bz#958750]- Resolves: bz#958750 (QMP event shows incorrect balloon value when balloon size is grater than or equal to 4G)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0896");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0896.html");
script_cve_id("CVE-2013-2007");
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
  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-guest-agent-win32", rpm:"qemu-guest-agent-win32~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

