# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1913.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122872");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-02-05 14:01:41 +0200 (Fri, 05 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1913");
script_tag(name: "insight", value: "ELSA-2014-1913 -  ruby193-ruby security update - [1.9.3.484-50.0.1]- fix build issue: self test report 'dh key to small'[1.9.3.484-50]- Fix off-by-one stack-based buffer overflow in the encodes() function (CVE-2014-4975). Related: rhbz#1164004- Fix REXML billion laughs attack via parameter entity expansion (CVE-2014-8080). Related: rhbz#1164004- REXML incomplete fix for CVE-2014-8080 (CVE-2014-8090). Related: rhbz#1164004"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1913");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1913.html");
script_cve_id("CVE-2014-8080","CVE-2014-8090","CVE-2014-4975");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"ruby193-ruby", rpm:"ruby193-ruby~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-ruby-devel", rpm:"ruby193-ruby-devel~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-ruby-doc", rpm:"ruby193-ruby-doc~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-ruby-irb", rpm:"ruby193-ruby-irb~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-ruby-libs", rpm:"ruby193-ruby-libs~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-ruby-tcltk", rpm:"ruby193-ruby-tcltk~1.9.3.484~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-bigdecimal", rpm:"ruby193-rubygem-bigdecimal~1.1.0~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-io-console", rpm:"ruby193-rubygem-io-console~0.3~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-json", rpm:"ruby193-rubygem-json~1.5.5~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-minitest", rpm:"ruby193-rubygem-minitest~2.5.1~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-rake", rpm:"ruby193-rubygem-rake~0.9.2.2~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygem-rdoc", rpm:"ruby193-rubygem-rdoc~3.9.5~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygems", rpm:"ruby193-rubygems~1.8.23~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby193-rubygems-devel", rpm:"ruby193-rubygems-devel~1.8.23~50.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

