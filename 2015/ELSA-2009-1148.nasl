# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1148.nasl 4513 2016-11-15 09:37:48Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122468");
script_version("$Revision: 4513 $");
script_tag(name:"creation_date", value:"2015-10-08 14:46:00 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 10:37:48 +0100 (Tue, 15 Nov 2016) $");
script_name("Oracle Linux Local Check: ELSA-2009-1148");
script_tag(name: "insight", value: "ELSA-2009-1148 -  httpd security update - [2.2.3-22.0.1.el5_3.2]- Replace index.html with Oracle's index page oracle_index.html- Update vstring and distro in specfile[2.2.3-22.el5_3.2]- add security fixes for CVE-2009-1890, CVE-2009-1891 (#509782)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1148");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1148.html");
script_cve_id("CVE-2009-1890","CVE-2009-1891");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_summary("Oracle Linux Local Security Checks ELSA-2009-1148");
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
  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~22.0.1.el5_3.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~22.0.1.el5_3.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~22.0.1.el5_3.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~22.0.1.el5_3.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

