# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0246.nasl 6170 2017-05-19 09:03:42Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123456");
script_version("$Revision: 6170 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:03 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-05-19 11:03:42 +0200 (Fri, 19 May 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0246");
script_tag(name: "insight", value: "ELSA-2014-0246 -  gnutls security update - [2.8.5-13]- fix CVE-2014-0092 (#1069890)[2.8.5-12]- fix CVE-2013-2116 - fix DoS regression in CVE-2013-1619 upstream patch (#966754)[2.8.5-11]- fix CVE-2013-1619 - fix TLS-CBC timing attack (#908238)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0246");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0246.html");
script_cve_id("CVE-2014-0092");
script_tag(name:"cvss_base", value:"5.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
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
  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.8.5~13.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~2.8.5~13.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnutls-guile", rpm:"gnutls-guile~2.8.5~13.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~2.8.5~13.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

