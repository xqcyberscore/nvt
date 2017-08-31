# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1083.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123105");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:26 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1083");
script_tag(name: "insight", value: "ELSA-2015-1083 -  abrt security update - abrt[2.1.11-22.0.1]- Drop libreport-rhel and libreport-plugin-rhtsupport requires[2.1.11-22]- do not open the build_ids file as the user abrt- do not unlink failed and big user core files- Related: #1212819, #1216973[2.1.11-21]- validate all D-Bus method arguments- Related: #1214610[2.1.11-20]- remove the old dump directories during upgrade- abrt-action-install-debuginfo-to-abrt-cache: sanitize arguments and umask- fix race conditions and directory traversal issues in abrt-dbus- use /var/spool/abrt instead of /var/tmp/abrt- make the problem directories owned by root and the group abrt- validate uploaded problem directories in abrt-handle-upload- don't override files with user core dump files- fix symbolic link and race condition flaws- Resolves: #1211969, #1212819, #1212863, #1212869- Resolves: #1214453, #1214610, #1216973, #1218583libreport[2.1.11-23.0.1]- Update workflow xml for Oracle [18945470]- Add oracle-enterprise.patch and oracle-enterprise-po.patch- Remove libreport-plugin-rhtsupport and libreport-rhel- Added orabug20390725.patch to remove redhat reference [bug 20390725]- Added Bug20357383.patch to remove redhat reference [bug 20357383][2.1.11-23]- do not open files outside a dump directory- Related: #1217484[2.1.11-22]- switch the default dump dir mode to 0750- harden against directory traversal, crafted symbolic links- avoid race-conditions in dump dir opening- Resolves: #1212096, #1217499, #1218610, #1217484"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1083");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1083.html");
script_cve_id("CVE-2015-1869","CVE-2015-1870","CVE-2015-3142","CVE-2015-3147","CVE-2015-3150","CVE-2015-3151","CVE-2015-3159","CVE-2015-3315");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-pstoreoops", rpm:"abrt-addon-pstoreoops~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-upload-watch", rpm:"abrt-addon-upload-watch~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-addon-xorg", rpm:"abrt-addon-xorg~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-console-notification", rpm:"abrt-console-notification~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-dbus", rpm:"abrt-dbus~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-gui-devel", rpm:"abrt-gui-devel~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-gui-libs", rpm:"abrt-gui-libs~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-python", rpm:"abrt-python~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-python-doc", rpm:"abrt-python-doc~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-retrace-client", rpm:"abrt-retrace-client~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.1.11~22.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-anaconda", rpm:"libreport-anaconda~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-compat", rpm:"libreport-compat~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-filesystem", rpm:"libreport-filesystem~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-plugin-ureport", rpm:"libreport-plugin-ureport~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-rhel-anaconda-bugzilla", rpm:"libreport-rhel-anaconda-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-rhel-bugzilla", rpm:"libreport-rhel-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-web", rpm:"libreport-web~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libreport-web-devel", rpm:"libreport-web-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

