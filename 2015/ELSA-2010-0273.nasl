# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0273.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122376");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:46 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0273");
script_tag(name: "insight", value: "ELSA-2010-0273 -  curl security, bug fix and enhancement update - [7.15.5-9]- http://curl.haxx.se/docs/adv_20100209.html (#565408)[7.15.5-8]- mention lack of IPv6, FTPS and LDAP support while using a socks proxy (#473128)- avoid tight loop if an upload connection is broken (#479967)- add options --ftp-account and --ftp-alternative-to-user to program help (#517084)- fix crash when reusing connection after negotiate-auth (#517199)- support for CRL loading from a PEM file (#532069)[7.15.5-7]- sync patch for CVE-2007-0037 with 5.3.ZRelated: #485290[7.15.5-6]- fix CVE-2009-2417Resolves: #516258[7.15.5-5]- forwardport one hunk from upstream curl-7.15.1Related: #485290[7.15.5-4]- fix hunk applied to wrong place due to nonzero patch fuzzRelated: #485290[7.15.5-3]- fix CVE-2007-0037Resolves: #485290"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0273");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0273.html");
script_cve_id("CVE-2010-0734");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.15.5~9.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"curl-devel", rpm:"curl-devel~7.15.5~9.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

