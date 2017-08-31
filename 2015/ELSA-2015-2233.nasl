# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2233.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122783");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-25 13:18:50 +0200 (Wed, 25 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2233");
script_tag(name: "insight", value: "ELSA-2015-2233 -  tigervnc security, bug fix, and enhancement update - [1.3.1-3]- Do not mention that display number is required in the file name Resolves: bz#1195266[1.3.1-2]- Resolves: bz#1248422 CVE-2014-8240 CVE-2014-8241 tigervnc: various flaws[1.3.1-1]- Drop unecessary patches- Re-base to 1.3.1 (bug #1199453)- Re-build against re-based xserver (bug #1194898)- Check the return value from XShmAttach (bug #1072733)- Add missing part of xserver114.patch (bug #1140603)- Keep pointer in sync (bug #1100661)- Make input device class global (bug #1119640)- Add IPv6 support (bug #1162722)- Set initial mode as prefered (bug #1181287)- Do not mention that display number is required in the file name (bug #1195266)- Enable Xinerama extension (bug #1199437)- Specify full path for runuser command (bug #1208817)[1.2.80-0.31.20130314svn5065]- Rebuilt against xorg-x11-server to pick up ppc64le fix (bug #1140424)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2233");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2233.html");
script_cve_id("CVE-2014-8240","CVE-2014-8241");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-server-applet", rpm:"tigervnc-server-applet~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tigervnc-server-module", rpm:"tigervnc-server-module~1.3.1~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

