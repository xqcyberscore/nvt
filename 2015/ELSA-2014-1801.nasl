# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1801.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123258");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:23 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1801");
script_tag(name: "insight", value: "ELSA-2014-1801 -  shim security update - shim[0.7-8.0.1]- update Oracle Linux certificates (Alexey Petrenko)- replace securebootca.cer (Alexey Petrenko)[0.7-8]- out-of-bounds memory read flaw in DHCPv6 packet processing Resolves: CVE-2014-3675- heap-based buffer overflow flaw in IPv6 address parsing Resolves: CVE-2014-3676- memory corruption flaw when processing Machine Owner Keys (MOKs) Resolves: CVE-2014-3677[0.7-7]- Use the right key for ARM Aarch64.[0.7-6]- Preliminary build for ARM Aarch64.shim-signed[0.7-8.0.1]- Oracle Linux certificates (Alexey Petrenko)[0.7-8]- out-of-bounds memory read flaw in DHCPv6 packet processing Resolves: CVE-2014-3675- heap-based buffer overflow flaw in IPv6 address parsing Resolves: CVE-2014-3676- memory corruption flaw when processing Machine Owner Keys (MOKs) Resolves: CVE-2014-3677[0.7-5.2]- Get the right signatures on shim-redhat.efi Related: rhbz#1064449[0.7-5.1]- Update for signed shim for RHEL 7 Resolves: rhbz#1064449"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1801");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1801.html");
script_cve_id("CVE-2014-3675","CVE-2014-3676","CVE-2014-3677");
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
  if ((res = isrpmvuln(pkg:"mokutil", rpm:"mokutil~0.7~8.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"shim", rpm:"shim~0.7~8.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"shim-unsigned", rpm:"shim-unsigned~0.7~8.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

