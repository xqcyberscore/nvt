# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0400.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122360");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:32 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0400");
script_tag(name: "insight", value: "ELSA-2010-0400 -  tetex security update - [3.0-33.8.el5.5]- unify patches for CVE-2010-0739 and CVE-2010-1440[3.0-33.8.el5.4]- fix CVE-2010-1440 (#586819)[3.0-33.8.el5.3]- initialize data in arithmetic coder elsewhere (CVE-2009-0146)[3.0-33.8.el5.2]- initialize dataLen to properly fix CVE-2009-0146[3.0-33.8.el5.1]- fix CVE-2010-0739 CVE-2010-0829 CVE-2007-5936 CVE-2007-5937CVE-2009-0146 CVE-2009-0195 CVE-2009-0147 CVE-2009-0166 CVE-2009-0799CVE-2009-0800 CVE-2009-1179 CVE-2009-1180 CVE-2009-1181 CVE-2009-1182CVE-2009-1183 CVE-2009-0791 CVE-2009-3608 CVE-2009-3609Resolves: #577328"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0400");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0400.html");
script_cve_id("CVE-2009-0146","CVE-2009-0147","CVE-2009-0166","CVE-2009-0195","CVE-2009-0791","CVE-2009-0799","CVE-2009-0800","CVE-2009-1179","CVE-2009-1180","CVE-2009-1181","CVE-2009-1182","CVE-2009-1183","CVE-2009-3608","CVE-2009-3609","CVE-2010-0739","CVE-2010-0829","CVE-2010-1440");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-fonts", rpm:"tetex-fonts~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~3.0~33.8.el5_5.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

