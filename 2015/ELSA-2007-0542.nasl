# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0542.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122640");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:49:59 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0542");
script_tag(name: "insight", value: "ELSA-2007-0542 -  mcstrans security and bug fix update - [0.2.6-1]- Don't allow categories > 1023Resolves: #288941[0.2.3-1]- Additional fix to handle ssh root/sysadm_r/s0:c1,c2Resolves: #224637[0.2.1-1]- Rewrite to handle MLS properlyResolves: #225355[0.1.10-2]- Cleanup memory when complete[0.1.10-1]- Fix Memory LeakResolves: #218173[0.1.9-1]- Add -pie- Fix compiler warnings- Fix Memory LeakResolves: #218173[0.1.8-3]- Fix subsys locking in init script[0.1.8-1]- Only allow one version to run- rebuild[0.1.7-1]- Apply sgrubb patch to only call getpeercon on translations[0.1.6-1]- Exit gracefully when selinux is not enabled[0.1.5-1]- Fix sighup handling[0.1.4-1]- Add patch from sgrubb- Fix 64 bit size problems- Increase the open file limit- Make sure maximum size is not exceeded[0.1.3-1]- Move initscripts to /etc/rc.d/init.d[0.1.2-1]- Drop Privs[0.1.1-1]- Initial Version- This daemon reuses the code from libsetrans"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0542");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0542.html");
script_cve_id("CVE-2007-4570");
script_tag(name:"cvss_base", value:"1.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"mcstrans", rpm:"mcstrans~0.2.6~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

