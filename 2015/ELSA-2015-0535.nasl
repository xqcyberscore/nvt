# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0535.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123171");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0535");
script_tag(name: "insight", value: "ELSA-2015-0535 -  GNOME Shell security, bug fix, and enhancement update - clutter[1.14.4-12]- Include upstream patch to prevent a crash when hitting hardware limits Resolves: rhbz#1115162[1.14.4-11]- Fix a typo in the Requires[1.14.4-10]- Add patch for quadbuffer stereo suppport Resolves: rhbz#1108891cogl[1.14.1-6]- Add patches for quadbuffer stereo suppport Resolves: rhbz#1108890[1.14.0-5.2]- Ensure the glBlitFramebuffer case is not hit for swrast, since that's still broken.gnome-shell[3.8.4-45]- Don't inform GDM about session changes that came from GDM Resolves: #1163474[3.8.4-44]- If password authentication is disabled and smartcard authentication is enabled and smartcard isn't plugged in at start up, prompt user for smartcard Resolves: #1159385[3.8.4-43]- Support long login banner messages more effectively Resolves: #1110036[3.8.4-42]- Respect disk-writes lockdown setting Resolves: rhbz#1154122[3.8.4-41]- Disallow consecutive screenshot requests to avoid an OOM situation Resolves: rhbz#1154107[3.8.4-41]- Add option to limit app switcher to current workspace Resolves: rhbz#1101568[3.8.4-40]- Try harder to use the default calendar application Resolves: rhbz#1052201[3.8.4-40]- Update workspace switcher fix Resolves: rhbz#1092102[3.8.4-39]- Validate screenshot parameters Resolves: rhbz#1104694[3.8.4-38]- Fix shrinking workspace switcher Resolves: rhbz#1092102[3.8.4-38]- Update fix for vertical monitor layouts to upstream fix Resolves: rhbz#1075240[3.8.4-38]- Fix traceback introduced in 3.8.4-36 when unlocking via user switcher Related: #1101333[3.8.4-37]- Fix problems with LDAP and disable-user-list=TRUE Resolves: rhbz#1137041[3.8.4-36]- Fix login screen focus issue following idle Resolves: rhbz#1101333[3.8.4-35]- Disallow cancel from login screen before login attempt has been initiated. Resolves: rhbz#1109530[3.8.4-34]- Disallow cancel from login screen after login is already commencing. Resolves: rhbz#1079294[3.8.4-33]- Add a patch for quadbuffer stereo suppport Resolves: rhbz#1108893mutter[3.8.4.16]- Fix window placement regression Resolves: rhbz#1153641[3.8.4-15]- Fix delayed mouse mode Resolves: rhbz#1149585[3.8.4-14]- Preserve window placement on monitor changes Resolves: rhbz#1126754[3.8.4-13]- Improve handling of vertical monitor layouts Resolves: rhbz#1108322[3.8.4-13]- Add patches for quadbuffer stereo suppport Fix a bad performance problem drawing window thumbnails Resolves: rhbz#861507"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0535");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0535.html");
script_cve_id("CVE-2014-7300");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"clutter", rpm:"clutter~1.14.4~12.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"clutter-devel", rpm:"clutter-devel~1.14.4~12.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"clutter-doc", rpm:"clutter-doc~1.14.4~12.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cogl", rpm:"cogl~1.14.0~6.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cogl-devel", rpm:"cogl-devel~1.14.0~6.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cogl-doc", rpm:"cogl-doc~1.14.0~6.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.8.4~45.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-shell-browser-plugin", rpm:"gnome-shell-browser-plugin~3.8.4~45.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mutter", rpm:"mutter~3.8.4~16.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mutter-devel", rpm:"mutter-devel~3.8.4~16.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

