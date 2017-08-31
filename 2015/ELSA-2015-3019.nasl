# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-3019.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123144");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 09:48:27 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-3019");
script_tag(name: "insight", value: "ELSA-2015-3019 - Unbreakable Enterprise kernel security update - kernel-uek[3.8.13-68.1.2]- IB/core: Prevent integer overflow in ib_umem_get address arithmetic (Shachar Raindel) [Orabug: 20799875] {CVE-2014-8159} {CVE-2014-8159}[3.8.13-68.1.1]- xen-pciback: limit guest control of command register (Jan Beulich) [Orabug: 20697017] {CVE-2015-2150} {CVE-2015-2150}- net: sctp: fix slab corruption from use after free on INIT collisions (Daniel Borkmann) [Orabug: 20780347] {CVE-2015-1421}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-3019");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-3019.html");
script_cve_id("CVE-2014-8159","CVE-2015-1421","CVE-2015-2150");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.1.2.el7uek~0.4.3~4.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.1.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.1.2.el6uek~0.4.3~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.1.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

