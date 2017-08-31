# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0774.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123886");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0774");
script_tag(name: "insight", value: "ELSA-2012-0774 -  libguestfs security, bug fix, and enhancement update - [1:1.16.19-1]- Rebase to libguestfs 1.16.19 resolves: rhbz#719879- Rebuild against augeas 0.9.0-3.el6 related: rhbz#808662- Fix: Don't abort inspection if mdadm.conf ARRAY doesn't have a uuid.- Switch back to git for patch management.[1:1.16.18-2]- Rebase to libguestfs 1.16.18 resolves: rhbz#719879- Fix: guestfs_last_error not set when qemu fails early during launch resolves: rhbz#811673- Fix: RFE: virt-sysprep: hostname can not be changed on rhel system (RHBZ#811112)- Fix: RFE: virt-sysprep: net-hwaddr not removed from ifcfg-* files on rhel (RHBZ#811117)- Fix: inspection fails on ubuntu 10.04 guest with encrypted swap (RHBZ#811872)- Fix: cannot open disk images which are symlinks to files that contain ':' (colon) character (RHBZ#812092)- BR gettext-devel so we can rerun autoconf.[1:1.16.15-1]- Rebase to libguestfs 1.16.15 resolves: rhbz#719879- Fix: inspection doesn't recognize Fedora 17+ (RHBZ#809401)[1:1.16.14-1]- Rebase to libguestfs 1.16.14 resolves: rhbz#719879- virt-sysprep should use virt-inspector2 resolves: rhbz#807557- Fix: mkfs blocksize option breaks when creating btrfs resolves: rhbz#807905[1:1.16.12-1]- Rebase to libguestfs 1.16.12 resolves: rhbz#719879- Fix: could not locate HKLM\SYSTEM\MountedDevices resolves: rhbz#803699[1:1.16.10-1]- Rebase to libguestfs 1.16.10 resolves: rhbz#719879- Fix: libguestfs holds open file descriptors when handle is launched resolves: rhbz#801788- Fix: Document for set-pgroup need to be updated resolves: rhbz#801273- Fix: Possible null dereference and resource leaks resolves: rhbz#801298[1:1.16.8-1]- Rebase to libguestfs 1.16.8 resolves: rhbz#719879- Fix set_autosync function so it is not 'ConfigOnly' resolves: rhbz#796520- Fix header compilation for C++ resolves: rhbz#799695[1:1.16.6-1]- Rebase to libguesfs 1.16.6 resolves: rhbz#798197, rhbz#797760,rhbz#790958,rhbz#798980,rhbz#795322,rhbz#796520- Fix virt-inspector2 man page.[1:1.16.5-1]- Rebase to libguestfs 1.16.5 resolves: rhbz#679737, rhbz#789960[1:1.16.4-1]- Rebase to libguestfs 1.16.4 resolves: rhbz#788642[1:1.16.3-1]- Rebase to libguestfs 1.16.3 resolves: rhbz#679737, rhbz#769359, rhbz#785305[1:1.16.2-1]- Rebase to libguestfs 1.16.2 resolves: rhbz#719879[1:1.16.1-1]- Rebase to libguestfs 1.16.1- Disable tests (probably because we are hitting https://lists.gnu.org/archive/html/qemu-devel/2010-02/threads.html#00823 ) resolves: rhbz#719879[1:1.14.7-4]- Continue with rebase to libguestfs 1.14.7 resolves: rhbz#719879[1:1.14.7-1]- Rebase to libguestfs 1.14.7 resolves: rhbz#719879"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0774");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0774.html");
script_cve_id("CVE-2012-2690");
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
  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-devel", rpm:"libguestfs-devel~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-java-devel", rpm:"libguestfs-java-devel~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-javadoc", rpm:"libguestfs-javadoc~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-libguestfs", rpm:"ocaml-libguestfs~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-libguestfs-devel", rpm:"ocaml-libguestfs-devel~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libguestfs", rpm:"python-libguestfs~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-libguestfs", rpm:"ruby-libguestfs~1.16.19~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

