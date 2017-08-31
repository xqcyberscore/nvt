# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0204.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122880");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-02-18 07:27:22 +0200 (Thu, 18 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0204");
script_tag(name: "insight", value: "ELSA-2016-0204 -  389-ds-base security and bug fix update - [1.3.4.0-26]- release 1.3.4.0-26- Resolves: bug 1299346 - deadlock on connection mutex (DS 48341)[1.3.4.0-25]- release 1.3.4.0-25- Resolves: bug 1299757 - CVE-2016-0741 389-ds-base: Worker threads do not detect abnormally closed connections causing DoS[1.3.4.0-24]- release 1.3.4.0-24- Resolves: bug 1298105 - 389-ds hanging after a few minutes of operation (DS 48406)[1.3.4.0-23]- release 1.3.4.0-23- Resolves: bug 1295684 - many attrlist_replace errors in connection with cleanallruv (DS 48283)[1.3.4.0-22]- release 1.3.4.0-22- Resolves: bug 1290725 - SimplePagedResults -- in the search error case, simple paged results slot was not released. (DS 48375)- Resolves: bug 1290726 - The 'eq' index does not get updated properly when deleting and re-adding attributes in the same modify operation (DS 48370)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0204");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0204.html");
script_cve_id("CVE-2016-0741");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.4.0~26.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.4.0~26.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.4.0~26.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

