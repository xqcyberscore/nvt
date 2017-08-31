# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0517.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123703");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:26 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0517");
script_tag(name: "insight", value: "ELSA-2013-0517 -  util-linux-ng security, bug fix and enhancement update - [2.17.2-12.9]- fix #892471 - CVE-2013-0157 mount folder existence information disclosure[2.17.2-12.8]- fix #679833 - [RFE] tailf should support - fix #719927 - [RFE] add adjtimex --compare functionality to hwclock- fix #730272 - losetup does not warn if backing file is < 512 bytes- fix #730891 - document cfdisk and sfdisk incompatibility with 4096-bytes sectors- fix #736245 - lscpu segfault on non-uniform cpu configuration- fix #783514 - default barrier setting for EXT3 filesystems in mount manpage is wrong- fix #790728 - blkid ignores swap UUIDs if the first byte is a zero byte- fix #818621 - lsblk should not open device it prints info about- fix #819945 - hwclock --systz causes a system time jump- fix #820183 - mount(8) man page should include relatime in defaults definition- fix #823008 - update to the latest upstream lscpu and chcpu- fix #837935 - lscpu coredumps on a system with 158 active processors- fix #839281 - inode_readahead for ext4 should be inode_readahead_blks- fix #845477 - Duplicate SElinux mount options cause mounting from the commandline to fail- fix #845971 - while reading /etc/fstab, mount command returns a device before a directory- fix #858009 - login doesn't update /var/run/utmp properly- fix #809449 - Backport inverse tree (-s) option for lsblk and related patches- fix #809139 - lsblk option -D missing in manpage"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0517");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0517.html");
script_cve_id("CVE-2013-0157");
script_tag(name:"cvss_base", value:"2.1");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"util-linux-ng", rpm:"util-linux-ng~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.17.2~12.9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

