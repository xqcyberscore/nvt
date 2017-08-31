# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1982.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123226");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1982");
script_tag(name: "insight", value: "ELSA-2014-1982 -  xorg-x11-server security update - [1.1.1-48.107.0.1.el5_11]- Added oracle-enterprise-detect.patch- Replaced 'Red Hat' in spec file[1.1.1-48.107]- CVE-2014-8091 denial of service due to unchecked malloc in client authentication (#1168680)- CVE-2014-8092 integer overflow in X11 core protocol requests when calculating memory needs for requests (#1168684)- CVE-2014-8097 out of bounds access due to not validating length or offset values in DBE extension (#1168705)- CVE-2014-8095 out of bounds access due to not validating length or offset values in XInput extension (#1168694)- CVE-2014-8096 out of bounds access due to not validating length or offset values in XC-MISC extension(#1168700)- CVE-2014-8099 out of bounds access due to not validating length or offset values in XVideo extension (#1168710)- CVE-2014-8100 out of bounds access due to not validating length or offset values in Render extension (#1168711)- CVE-2014-8102 out of bounds access due to not validating length or offset values in XFixes extension (#1168714)- CVE-2014-8101 out of bounds access due to not validating length or offset values in RandR extension (#1168713)- CVE-2014-8093 xorg-x11-server: integer overflow in GLX extension requests when calculating memory needs for requests (#1168688)- CVE-2014-8098 xorg-x11-server: out of bounds access due to not validating length or offset values in GLX extension (#1168707)[1.1.1-48.104]- xserver-1.1.1-randr-config-timestamps.patch: Backport timestamp comparison fix from upstream RANDR code (#1006076)[1.1.1-48.103]- CVE-2013-6424: Fix OOB in trapezoid rasterization"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1982");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1982.html");
script_cve_id("CVE-2014-8091","CVE-2014-8092","CVE-2014-8093","CVE-2014-8095","CVE-2014-8096","CVE-2014-8097","CVE-2014-8098","CVE-2014-8099","CVE-2014-8100","CVE-2014-8101","CVE-2014-8102");
script_tag(name:"cvss_base", value:"6.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvnc-source", rpm:"xorg-x11-server-Xvnc-source~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

