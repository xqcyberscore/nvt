# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2623.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122805");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-12-16 11:36:46 +0200 (Wed, 16 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2623");
script_tag(name: "insight", value: "ELSA-2015-2623 -  grub2 security and bug fix update - [2.02-0.33.0.1]- Fix comparison in patch for 18504756- Remove symlink to grub environment file during uninstall on EFI platforms [bug 19231481]- update Oracle Linux certificates (Alexey Petrenko)- Put 'with' in menuentry instead of 'using' [bug 18504756]- Use different titles for UEK and RHCK kernels [bug 18504756][2.02-0.33]- Don't remove 01_users, it's the wrong thing to do. Related:rhbz1290089[2.02-0.32]- Rebuild for .z so the release number is different. Related: rhbz#1290089[2.02-0.31]- More work on handling of GRUB2_PASSWORD Resolves: rhbz#1290089[2.02-0.30]- Fix security issue when reading username and password Resolves: CVE-2015-8370- Do a better job of handling GRUB_PASSWORD Resolves: rhbz#1290089"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2623");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2623.html");
script_cve_id("CVE-2015-8370");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.33.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.33.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-efi-modules", rpm:"grub2-efi-modules~2.02~0.33.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.33.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

