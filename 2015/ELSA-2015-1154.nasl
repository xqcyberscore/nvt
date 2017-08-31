# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1154.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123094");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:17 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1154");
script_tag(name: "insight", value: "ELSA-2015-1154 -  libreswan security, bug fix and enhancement update - [3.12-10.1.0.1]- add libreswan-oracle.patch to detect Oracle Linux distro[3.12-10.1]- Resolves: rhbz#1226407 CVE-2015-3204 libreswan: crafted IKE packet causes daemon restart[3.12-10]- Resolves: rhbz#1213652 Support CAVS [updated another prf() free symkey, bogus fips mode fix][3.12-9]- Resolves: rhbz#1213652 Support CAVS [updated to kill another copy of prf()]- Resolves: rhbz#1208023 Libreswan with IPv6 [updated patch by Jaroslav Aster]- Resolves: rhbz#1208022 libreswan ignores module blacklist [updated modprobe handling][3.12-8]- Resolves: rhbz#1213652 Support CAVS testing of the PRF/PRF+ functions[3.12-7]- Resolves: rhbz#1208022 libreswan ignores module blacklist rules- Resolves: rhbz#1208023 Libreswan with IPv6 in RHEL7 fails after reboot- Resolves: rhbz#1211146 pluto crashes in fips mode[3.12-6]- Resolves: rhbz#1198650 SELinux context string size limit- Resolves: rhbz#1198649 Add new option for BSI random requirement"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1154");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1154.html");
script_cve_id("CVE-2015-3204");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.12~10.1.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

