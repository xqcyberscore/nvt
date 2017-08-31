# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0342.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122682");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:51:03 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0342");
script_tag(name: "insight", value: "ELSA-2007-0342 -  Moderate: ipsec-tools security update - [0.6.5-8] - Upstream fix for Racoon DOS, informational delete must be encrypted - Resolves: rhbz#235388 - CVE-2007-1841 ipsec-tools racoon DoS [0.6.5-7] - Resolves: #218386 labeled ipsec does not work over loopback [0.6.5-6.6] - Related: #232508 add auditing to racoon [0.6.5-6.5] - Resolves: #235680 racoon socket descriptor exhaustion [0.6.5-6.4] - Resolves: #236121 increase buffer for context [0.6.5-6.3] - Resolves: #234491 kernel sends ACQUIRES that racoon is not catching - Resolves: #218386 labeled ipsec does not work over loopback [0.6.5-6.2.el5] - fix for setting the security context into a proposal (3264bit) - Resolves: rhbz#232508"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0342");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0342.html");
script_cve_id("CVE-2007-1841");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~8.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

