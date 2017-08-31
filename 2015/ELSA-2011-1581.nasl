# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1581.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122037");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1581");
script_tag(name: "insight", value: "ELSA-2011-1581 -  ruby security, bug fix, and enhancement update - [1.8.7.352-3]- mkconfig.rb: fix for continued lines. * ruby-1.8.7-p352-mkconfig.rb-fix-for-continued-lines.patch- Resolves: rhbz#730287[1.8.7.352-2]- Fix of ruby interpreter crash in FIPS mode. * ruby-1.8.7-FIPS.patch- Resolves: rhbz#717709[1.8.7.352-1]- Update to Ruby 1.8.7-p352. * Remove Patch43: ruby-1.8.7-CVE-2011-1004.patch; subsumed * Remove Patch44: ruby-1.8.7-CVE-2011-1005.patch; subsumed * Remove Patch200: ruby-1.8.7-webrick-CVE.patch; subsumed- Resolves: rhbz#706332- Fix of conflict between 32bit and 64bit library versions.- Resolves: rhbz#674787- Add systemtap static probes.- Resolves: rhbz#673162- Remove duplicate path entry- Resolves: rhbz#722887[1.8.7.299-8]- Address CVE-2011-1004 'Symlink race condition by removing directory trees in fileutils module' * ruby-1.8.7-CVE-2011-1004.patch- Address CVE-2011-1005 'Untrusted codes able to modify arbitrary strings' * ruby-1.8.7-CVE-2011-1005.patch- Address CVE-2011-0188 'memory corruption in BigDecimal on 64bit platforms' * ruby-1.8.7-CVE-2011-0188.patch- Resolves: rhbz#709964"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1581");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1581.html");
script_cve_id("CVE-2011-2705","CVE-2011-3009");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-static", rpm:"ruby-static~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.7.352~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

