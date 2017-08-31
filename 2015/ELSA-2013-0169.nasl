# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0169.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123747");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:01 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0169");
script_tag(name: "insight", value: "ELSA-2013-0169 -  vino security update - [2.28.1-8]- Remove spurious 'e' from glib2-devel requirement[2.28.1-7]- Bump version number[2.28.1-6]- Bump version number[2.28.1-5]- Add reachability.patch Remove UI about whether the is only reachable locally or not. Fix for CVE-2011-1164 - Bug #553477[2.28.1-5]- Add upnp.patch Fix for CVE-2011-1165 - Bug #678846[2.28.1-5]- Add clipboard-leak.patch Fix for CVE-2012-4429 - Bug #857250[2.28.1-5]- Add vino-2.8.1-sanity-check-fb-update.patch Fix for CVE-2011-0904 and CVE-2011-0904 - Bugs #694456, #694455[2.28.1-4]- Translation updates. Related: rhbz 575682"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0169");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0169.html");
script_cve_id("CVE-2011-0904","CVE-2011-0905","CVE-2011-1164","CVE-2011-1165","CVE-2012-4429");
script_tag(name:"cvss_base", value:"5.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"vino", rpm:"vino~2.28.1~8.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

