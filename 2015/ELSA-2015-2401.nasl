# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2401.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122752");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:26 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2401");
script_tag(name: "insight", value: "ELSA-2015-2401 -  grub2 security, bug fix, and enhancement update - [2.02-0.29.0.1]- Fix comparison in patch for 18504756- Remove symlink to grub environment file during uninstall on EFI platforms [bug 19231481]- update Oracle Linux certificates (Alexey Petrenko)- Put 'with' in menuentry instead of 'using' [bug 18504756]- Use different titles for UEK and RHCK kernels [bug 18504756][2.02-0.29]- Fix DHCP6 timeouts due to failed network stack once more. Resolves: rhbz#1267139[2.02-0.28]- Once again, rebuild for the right build target. Resolves: CVE-2015-5281[2.02-0.27]- Remove multiboot and multiboot2 modules from the .efi builds; they should never have been there. Resolves: CVE-2015-5281[2.02-0.26]- Be more aggressive about trying to make sure we use the configured SNP device in UEFI. Resolves: rhbz#1257475[2.02-0.25]- Force file sync to disk on ppc64le machines. Resolves: rhbz#1212114[2.02-0.24]- Undo 0.23 and fix it a different way. Resolves: rhbz#1124074[2.02-0.23]- Reverse kernel sort order so they're displayed correctly. Resolves: rhbz#1124074[2.02-0.22]- Make upgrades work reasonably well with grub2-setpassword . Related: rhbz#985962[2.02-0.21]- Add a simpler grub2 password config tool Related: rhbz#985962- Some more coverity nits.[2.02-0.20]- Deal with some coverity nits. Related: rhbz#1215839 Related: rhbz#1124074[2.02-0.19]- Rebuild for Aarch64- Deal with some coverity nits. Related: rhbz#1215839 Related: rhbz#1124074[2.02-0.18]- Update for an rpmdiff problem with one of the man pages. Related: rhbz#1124074"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2401");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2401.html");
script_cve_id("CVE-2015-5281");
script_tag(name:"cvss_base", value:"2.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.29.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.29.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-efi-modules", rpm:"grub2-efi-modules~2.02~0.29.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.29.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

