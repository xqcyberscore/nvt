# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0132.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123764");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:13 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0132");
script_tag(name: "insight", value: "ELSA-2013-0132 -  autofs security, bug fix, and enhancement update - [5.0.1-0.rc2.177.0.1.el5] - apply fix from NetApp to use tcp before udp http://www.mail-archive.com/autofs@linux.kernel.org/msg07910.html (Bert Barbe) [orabug 6827898] [5.0.1-0.rc2.177.el5] - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server - disable hosts map HUP signal update. - Related: rhbz#714766 [5.0.1-0.rc2.176.el5] - bz859890 - no --timeout option usage demonstrated in auto.master FORMAT options man page section - add timeout option description to man page. - Resolves: rhbz#859890 [5.0.1-0.rc2.175.el5] - bz845503 - autofs initscript problems - fix status() return code now gets lost due to adding lock file check. - Related: rhbz#845503 [5.0.1-0.rc2.174.el5] - bz585058 - autofs5 init script times out before automount exits and incorrectly shows that autofs5 stop failed - fix don't wait forever for shutdown. - bz845503 - autofs initscript problems - don't unconditionaly call stop on restart. - fix usage message. - fix status return code when daemon is dead but lock file exists. - Related: rhbz#585058 rhbz#845503 [5.0.1-0.rc2.173.el5] - bz845503 - autofs initscript problems - don't use status() function in restart, it can't be relied upon. - Related: rhbz#845503 [5.0.1-0.rc2.172.el5] - bz845503 - autofs initscript problems - fix status call in restart must specify pid file name. - Related: rhbz#845503 [5.0.1-0.rc2.171.el5] - bz845503 - autofs initscript problems - make redhat init script more lsb compliant. - Resolves: rhbz#845503 [5.0.1-0.rc2.170.el5] - bz847101 - System unresponsiveness and CPU starvation when launching source code script - check negative cache much earlier. - dont use pthread_rwlock_tryrdlock(). - remove state machine timed wait. - Related: rhbz#847101 [5.0.1-0.rc2.169.el5] - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server - fix offset dir removal. - Related: rhbz#714766 [5.0.1-0.rc2.168.el5] - bz585058 - autofs5 init script times out before automount exits and incorrectly shows that autofs5 stop failed - make autofs wait longer for shutdown. - Resolves: rhbz#585058 [5.0.1-0.rc2.167.el5] - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server - fix expire race. - fix remount deadlock. - fix umount recovery of busy direct mount. - fix offset mount point directory removal. - remove move mount code. - fix remount of multi mount. - fix devce ioctl alloc path check. - refactor hosts lookup module. - remove cache update from parse_mount(). - add function to delete offset cache entry. - allow update of multi mount offset entries. - add hup signal handling to hosts map. - Resolves: rhbz#714766 [5.0.1-0.rc2.166.el5] - bz826633 - autofs crashes on lookup of a key containing a backslash - fix fix LDAP result leaks on error paths. - fix result null check in read_one_map(). - Resolves: rhbz#826633 [5.0.1-0.rc2.165.el5] - bz767428 - Fix autofs attempting to download entire LDAP map at startup - always read file maps multi map fix update. - report map not read when debug logging. - bz690404 - RFE: timeout option cannot be configured individually with multiple direct map entries - move timeout to map_source. - Resolves: rhbz#767428 rhbz#690404"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0132");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0132.html");
script_cve_id("CVE-2012-2697");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.1~0.rc2.177.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

