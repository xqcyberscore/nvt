# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0051.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122010");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:38 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0051");
script_tag(name: "insight", value: "ELSA-2012-0051 -  kvm security update - [kvm-83-239.0.1.el5_7.1]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch- Added kvm-Introduce-oel-machine-type.patch[kvm-83-239.el5_7.1]- kvm-e1000-prevent-buffer-overflow-when-processing-legacy.patch [bz#772079]- Resolves: bz#772079 (EMBARGOED CVE-2012-0029 qemu-kvm: e1000: process_tx_desc legacy mode packets heap overflow [rhel-5.7.z])- kvm-Fix-external-module-compat.c-not-to-use-unsupported-.patch [bz#753860] (build fix)- kvm-kernel-KVM-x86-Prevent-starting-PIT-timers-in-the-absence-o.patch [bz#770100]- Resolves: bz#770100 (CVE-2011-4622 kernel: kvm: pit timer with no irqchip crashes the system [rhel-5.7.z])[kvm-83-239.el5_7.1]- Updated kversion to 2.6.18-274.17.1.el5 to match build root"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0051");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0051.html");
script_cve_id("CVE-2012-0029","CVE-2011-4622");
script_tag(name:"cvss_base", value:"7.4");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~239.0.1.el5_7.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~239.0.1.el5_7.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~239.0.1.el5_7.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~239.0.1.el5_7.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~239.0.1.el5_7.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

