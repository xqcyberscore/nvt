# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1272.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123571");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:40 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1272");
script_tag(name: "insight", value: "ELSA-2013-1272 -  libvirt security and bug fix update - [0.10.2-18.0.1.el6_4.14]- Replace docs/et.png in tarball with blank image[0.10.2-18.el6_4.14]- spec: Update requirements to pick up rebuilt polkit (CVE-2013-4311)[0.10.2-18.el6_4.13]- spec: Fix messed up dependency on polkit (CVE-2013-4311)[0.10.2-18.el6_4.12]- Introduce APIs for splitting/joining strings (rhbz#1006265)- Rename virKillProcess to virProcessKill (rhbz#1006265)- Rename virPid{Abort, Wait} to virProcess{Abort, Wait} (rhbz#1006265)- Rename virCommandTranslateStatus to virProcessTranslateStatus (rhbz#1006265)- Move virProcessKill into virprocess.{h, c} (rhbz#1006265)- Move virProcess{Kill, Abort, TranslateStatus} into virprocess.{c, h} (rhbz#1006265)- Include process start time when doing polkit checks (rhbz#1006265)- Add support for using 3-arg pkcheck syntax for process (CVE-2013-4311)[0.10.2-18.el6_4.11]- Fix crash in remoteDispatchDomainMemoryStats (CVE-2013-4296)[0.10.2-18.el6_4.10]- qemu: Avoid leaking uri in qemuMigrationPrepareDirect (rhbz#984578)- qemu: Fix double free in qemuMigrationPrepareDirect (rhbz#984578)[when parsing a single device (rhbz#1003934)]- Plug leak in virCgroupMoveTask (rhbz#984556)- Fix invalid read in virCgroupGetValueStr (rhbz#984561)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1272");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1272.html");
script_cve_id("CVE-2013-4296","CVE-2013-4311");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

