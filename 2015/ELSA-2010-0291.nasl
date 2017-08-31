# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0291.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122375");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:45 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0291");
script_tag(name: "insight", value: "ELSA-2010-0291 -  gfs-kmod security, bug fix and enhancement update - [0.1.34-12]- Fixes a problem where improper locking commands can crash the system.- Resolves: rhbz#571298[0.1.34-11]- Fixes 'Resource tempory unavailable' for EWOULDBLOCK message with flocks on gfs file- Resolves: rhbz#515717[0.1.34-10]- Fixes 'Resource tempory unavailable' for EWOULDBLOCK message with flocks on gfs file- Resolves: rhbz#515717[0.1.34-9]- Change gfs freeze/unfreeze to use new standard- Resolves: rhbz#487610[0.1.34-8]- Fixes problem that produces this error message: fatal: assertion 'gfs_glock_is_locked_by_me(gl) && gfs_glock_is_held_excl(gl)' failed- Resolves: rhbz#471258[0.1.34-7]- GFS kernel panic, suid + nfsd with posix ACLs enabled- Resolves: rhbz#513885[0.1.34-5]- GFS: New mount option: -o errors=withdraw or panic- Resolves: rhbz#517145"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0291");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0291.html");
script_cve_id("CVE-2010-0727");
script_tag(name:"cvss_base", value:"4.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-gfs", rpm:"kmod-gfs~0.1.34~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-gfs-PAE", rpm:"kmod-gfs-PAE~0.1.34~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-gfs-xen", rpm:"kmod-gfs-xen~0.1.34~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

