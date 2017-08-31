# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0151.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123977");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:05 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0151");
script_tag(name: "insight", value: "ELSA-2012-0151 -  conga security, bug fix, and enhancement update - [0.12.2-51.0.1.el5]- Added conga-enterprise.patch- Added conga-enterprise-Carthage.patch to support OEL5- Replaced redhat logo image in conga-0.12.2.tar.gz[0.12.2-51]- Fix bz711494 (CVE-2011-1948 plone: reflected XSS vulnerability)- Fix bz771920 (CVE-2011-4924 Zope: Incomplete upstream patch for CVE-2010-1104/bz577019)[0.12.2-45]- Fix bz751359 (Add luci support for fence_ipmilan's -L option)[0.12.2-44]- Fix bz577019 (CVE-2010-1104 zope: XSS on error page)[0.12.2-42]- Fix bz755935 (luci_admin man page is misleading)- Fix bz755941 (luci_admin restore is not consistent)[0.12.2-40]- Fix excluding busy nodes not working properly in luci internals.[0.12.2-38]- Additional fix for bz734562 (Improve Luci's resource name validation)[0.12.2-37]- Additional fix for bz734562 (Improve Luci's resource name validation)[0.12.2-36]- Bump version of the luci database.[0.12.2-35]- Fix bz739600 (conga allows erroneous characters in resource)- Fix bz734562 (Improve Luci's resource name validation)[0.12.2-34]- Fix bz709478 (Ricci fails to detect if host if virtual machine capable)- Fix bz723000 (Modifying an existing shared resource will not update the reference in the cluster.conf)- Fix bz723188 (Luci does not allow to modify __max_restarts and __restart_expire_time for independent subtrees, only for non-critical resources)[0.12.2-33]- Fix bz732483 (Create new cluster fails with luci when installing packages.)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0151");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0151.html");
script_cve_id("CVE-2010-1104","CVE-2011-1948");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"luci", rpm:"luci~0.12.2~51.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.12.2~51.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

