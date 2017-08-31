# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0303.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123960");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0303");
script_tag(name: "insight", value: "ELSA-2012-0303 -  xorg-x11-server security and bug fix update - [1.1.1-48.90.0.1.el5]- Added oracle-enterprise-detect.patch- Replaced 'Red Hat' in spec file[1.1.1-48.90]- cve-2011-4028.patch: File existence disclosure vulnerability.[1.1.1-48.88]- cve-2011-4818.patch: Multiple input sanitization flaws in Render and GLX- xorg-x11-server-1.1.0-mesa-copy-sub-buffer.patch: Likewise.[1.1.1-48.87]- xserver-1.1.1-fbdev-iterate-modes.patch: fix fbdev driver not iterating across all modes of a certain dimension (#740497)[1.1.1-48.86]- xserver-1.1.1-midc-double-free.patch: Don't double-free the picture for the root window when using the mi (software) cursor path. (#674741)[1.1.1-48.85]- xserver-1.1.1-bigreqs-buffer-size.patch: Fix BIG-REQUESTS buffer size (#555000)[1.1.1-48.84]- xserver-1.1.1-xinerama-crash.patch: Fix a crash in XineramaQueryScreens when client is swapped (#588346)[1.1.1-48.83]- xserver-1.1.1-xephyr-keymap.patch: Fix types in Xephyr keymap setup (#454409)[1.1.1-48.82]- xserver-1.1.1-wideline-overflow.patch: Fix integer overflow in wide line renderer (#649810)[1.1.1-48.81]- Fix mouse stuck on edge (#529717)[1.1.1-48.80]- xserver-1.1.1-bs-crash.patch: Fix a crash in backing store. (#676270)[1.1.1-48.79]- xserver-1.1.1-randr-fix-mouse-crossing.patch: fix zaphod mouse crossing (#559964)[1.1.1-48.78]- cve-2010-1166.patch: Fix broken modulo math in Render and arc code. Identical to xserver-1.1.1-mod-macro-parens.patch in 5.5.z. (#582651)[1.1.1-48.77]- xserver-1.1.1-dbe-validate-gc.patch: Validate the GC against both front and back buffers (#596899)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0303");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0303.html");
script_cve_id("CVE-2011-4028");
script_tag(name:"cvss_base", value:"1.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvnc-source", rpm:"xorg-x11-server-Xvnc-source~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.90.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

