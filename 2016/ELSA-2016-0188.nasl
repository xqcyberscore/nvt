# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0188.nasl 7977 2017-12-04 08:28:58Z asteins $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122883");
script_version("$Revision: 7977 $");
script_tag(name:"creation_date", value:"2016-02-18 07:27:23 +0200 (Thu, 18 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-12-04 09:28:58 +0100 (Mon, 04 Dec 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0188");
script_tag(name: "insight", value: "ELSA-2016-0188 -  sos security and bug fix update - [3.2-35.0.1.3]- Recreated patch for [orabug 18913115]- Make the selinux plugin fixfiles option useful (John Haxby) [orabug 18913115]- Added remove_gpgstring.patch [Bug 18313898]- Added sos-oracle-enterprise.patch- Added sos-oraclelinux-vendor-vendorurl.patch[= 3.2-37]- [sosreport] prepare report in a private subdirectory (updated) Resolves: bz1290954[= 3.2-35.2]- [sosreport] prepare report in a private subdirectory (updated) Resolves: bz1290954[= 3.2-35.1]- [ceph] collect /var/lib/ceph and /var/run/ceph Resolves: bz1291347- [sosreport] prepare report in a private subdirectory Resolves: bz1290954"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0188");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0188.html");
script_cve_id("CVE-2015-7529");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~3.2~35.0.1.el7_2.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

