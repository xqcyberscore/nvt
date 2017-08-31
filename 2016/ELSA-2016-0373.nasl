# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0373.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122896");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-03-11 07:06:40 +0200 (Fri, 11 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0373");
script_tag(name: "insight", value: "ELSA-2016-0373 -  firefox security update - [38.7.0-1.0.1]- Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat one- Force requirement of newer gdk-pixbuf2 to ensure a proper update (Todd Vierling) [orabug 19847484][38.7.0-1]- Update to 38.7.0 ESR"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0373");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0373.html");
script_cve_id("CVE-2016-1952","CVE-2016-1954","CVE-2016-1957","CVE-2016-1958","CVE-2016-1960","CVE-2016-1961","CVE-2016-1962","CVE-2016-1964","CVE-2016-1965","CVE-2016-1966","CVE-2016-1973","CVE-2016-1974","CVE-2016-1977","CVE-2016-2790","CVE-2016-2791","CVE-2016-2792","CVE-2016-2793","CVE-2016-2794","CVE-2016-2795","CVE-2016-2796","CVE-2016-2797","CVE-2016-2798","CVE-2016-2799","CVE-2016-2800","CVE-2016-2801","CVE-2016-2802");
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
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.7.0~1.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.7.0~1.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.7.0~1.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

