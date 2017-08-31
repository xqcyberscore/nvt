# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0139.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123472");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0139");
script_tag(name: "insight", value: "ELSA-2014-0139 -  pidgin security update - [2.7.9-27.el6]- Fix regression in CVE-2013-6483.[2.7.9-26.el6]- Fix patch for CVE-2012-6152 (RH bug #1058242).[2.7.9-25.el6]- Add patch for CVE-2014-0020 (RH bug #1058242).[2.7.9-24.el6]- Add patch for CVE-2013-6490 (RH bug #1058242).[2.7.9-23.el6]- Add patch for CVE-2013-6489 (RH bug #1058242).[2.7.9-22.el6]- Add patch for CVE-2013-6487 (RH bug #1058242).[2.7.9-21.el6]- Add patch for CVE-2013-6477 (RH bug #1058242).[2.7.9-20.el6]- Add patch for CVE-2013-6485 (RH bug #1058242).[2.7.9-19.el6]- Add patch for CVE-2013-6484 (RH bug #1058242).[2.7.9-18.el6]- Add patch for CVE-2013-6483 (RH bug #1058242).[2.7.9-17.el6]- Add patch for CVE-2013-6482 (RH bug #1058242).[2.7.9-16.el6]- Add patch for CVE-2013-6481 (RH bug #1058242).[2.7.9-15.el6]- Add patch for CVE-2013-6479 (RH bug #1058242).[2.7.9-14.el6]- Turns out the previous patch is actually for CVE-2013-6478.[2.7.9-13.el6]- Add patch for CVE-2013-6477 (RH bug #1058242).[2.7.9-12.el6]- Add patch for CVE-2012-6152 (RH bug #1058242)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0139");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0139.html");
script_cve_id("CVE-2012-6152","CVE-2013-6477","CVE-2013-6478","CVE-2013-6479","CVE-2013-6481","CVE-2013-6482","CVE-2013-6483","CVE-2013-6484","CVE-2013-6485","CVE-2013-6487","CVE-2013-6489","CVE-2013-6490","CVE-2014-0020");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-docs", rpm:"pidgin-docs~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.7.9~27.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

