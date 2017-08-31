# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1793.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123006");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:49:57 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1793");
script_tag(name: "insight", value: "ELSA-2015-1793 -  qemu-kvm security fix update - [1.5.3-86.el7_1.6]- kvm-rtl8139-avoid-nested-ifs-in-IP-header-parsing-CVE-20.patch [bz#1248764]- kvm-rtl8139-drop-tautologous-if-ip-.-statement-CVE-2015-.patch [bz#1248764]- kvm-rtl8139-skip-offload-on-short-Ethernet-IP-header-CVE.patch [bz#1248764]- kvm-rtl8139-check-IP-Header-Length-field-CVE-2015-5165.patch [bz#1248764]- kvm-rtl8139-check-IP-Total-Length-field-CVE-2015-5165.patch [bz#1248764]- kvm-rtl8139-skip-offload-on-short-TCP-header-CVE-2015-51.patch [bz#1248764]- kvm-rtl8139-check-TCP-Data-Offset-field-CVE-2015-5165.patch [bz#1248764]- Resolves: bz#1248764 (CVE-2015-5165 qemu-kvm: Qemu: rtl8139 uninitialized heap memory information leakage to guest [rhel-7.1.z])"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1793");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1793.html");
script_cve_id("CVE-2015-5165");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7_1.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

