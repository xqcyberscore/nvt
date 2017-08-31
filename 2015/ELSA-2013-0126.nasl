# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0126.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123760");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:10 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0126");
script_tag(name: "insight", value: "ELSA-2013-0126 -  squirrelmail security and bug fix update - [1.4.8-21.0.2.el5] - remove Redhat splash screen images from source [1.4.8-21.0.1.el5] - remove Redhat splash screen images - add README instead of README.RedHat [1.4.8-21] - change charset for zh_CN and zh_TW to utf-8 (#508686) [1.4.8-20] - fix header encoding issue (#241861) - fix code producing warnings in the log (#475188) [1.4.8-19] - patch for CVE-2010-2813 modified wrong file (#808598) - correct requirement is mod_php not php (#789353) - comply with RFC2822 line length limits (#745469) - document that SELinux boolean httpd_can_sendmail needs to be turned on (#745380) - add support for big UIDs on 32bit machines (#450780) - do not corrupt html attachments (#359791)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0126");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0126.html");
script_cve_id("CVE-2012-2124");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~21.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

