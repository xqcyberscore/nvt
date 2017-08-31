# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0586.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122161");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:04 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0586");
script_tag(name: "insight", value: "ELSA-2011-0586 -  libguestfs security, bug fix, and enhancement update - [1.7.17-17]- Remove dependency on gfs2-utils. resolves: rhbz#695138[1.7.17-16]- Canonicalize /dev/vd* paths in virt-inspector code. resolves: rhbz#691724[1.7.17-15]- Fix trace segfault for non-daemon functions. resolves: rhbz#676788[1.7.17-14]- Add explicit BuildRequires for latest augeas. (RHBZ#677616)[1.7.17-13]- Rebuild to pick up new augeas lens (RHBZ#677616)[1.7.17-12]- Fix typo in virt-make-fs manual page. resolves: rhbz#673721- Add a grep-friendly string to LIBGUESTFS_TRACE output. resolves: rhbz#673477[1.7.17-11]- Only runtime require febootstrap-supermin-helper (not whole of febootstrap) (RHBZ#669840).[1.7.17-10]- Remove external hexedit script and make guestfish users set . This is because requiring emacs pulls in all of X (RHBZ#641494).[1.7.17-9]- Fix: guestfish fails when guest fstab entry does not exist (RHBZ#668611).[1.7.17-8]- Backport patches up to upstream 1.8.1. (RHBZ#613593)- Fixes: * guestfish: fails to tilde expand '~' when /home/ksharma unset (RHBZ#617440) * libguestfs: unknown filesystem /dev/fd0 (RHBZ#666577) * libguestfs: unknown filesystem label SWAP-sda2 (RHBZ#666578) * libguestfs: unknown filesystem /dev/hd{x} (cdrom) (RHBZ#666579) * virt-filesystems fails on guest with corrupt filesystem label (RHBZ#668115) * emphasize 'libguestfs-winsupport' in error output (RHBZ#627468)[1.7.17-4]- Backport patches up to upstream 1.8.0 _except_ for: * changes which require febootstrap 3.x * changes which were only relevant for other distros[1.7.17-3]- New upstream version 1.7.17, rebase for RHEL 6.1 (RHBZ#613593).- Require febootstrap >= 2.11.- Split out new libguestfs-tools-c package from libguestfs-tools. . This is so that the -tools-c package can be pulled in by people wanting to avoid a dependency on Perl, while -tools pulls in everything as before. . The C tools currently are: cat, df, filesystems, fish, inspector, ls, mount, rescue. . libguestfs-tools no longer pulls in guestfish.- guestfish no longer requires pod2text, hence no longer requires perl.- guestfish also depends on: less, man, vi, emacs.- Add BR db4-utils (although since RPM needs it, it not really necessary).- Runtime requires on db4-utils should be on core lib, not tools package.- Change all 'Requires: perl-Foo' to 'Requires: perl(Foo)'.- New manual pages containing example code.- Ship examples for C, OCaml, Ruby, Python.- Don't ship HTML versions of man pages.- Rebase no-fuse-test patch to latest version.- New tool: virt-filesystems.- Rename perl-libguestfs as perl-Sys-Guestfs (RHBZ#652587).- Remove guestfs-actions.h and guestfs-structs.h. Libguestfs now[header file.]- Add AUTHORS file from tarball.[1.6.2-4]- New upstream stable version 1.6.2, rebase for RHEL 6.1 (RHBZ#613593).- Remove previous patches which are now all upstream and in this new version.- BR febootstrap 2.10 (RHBZ#628849).- BR cryptsetup-luks for new LUKS encryption support.- ocaml-xml-light{,-devel} is no longer required to build.- guestfish is no longer dependent on virt-inspector.- Require the ruby package.- Disable PHP and Haskell bindings in configure (they wouldn't build anyway, but this will help people building from source).- Set sysconfdir in configure.- --enable-debug-command is no longer required by configure script.- New command 'virt-make-fs'.- Include virt-inspector2, upstream replacement for virt-inspector.- Provide hexedit replacement script for guestfish.- BR autotools, and rerun after applying patches."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0586");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0586.html");
script_cve_id("CVE-2010-3851");
script_tag(name:"cvss_base", value:"4.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"guestfish", rpm:"guestfish~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-devel", rpm:"libguestfs-devel~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-java-devel", rpm:"libguestfs-java-devel~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-javadoc", rpm:"libguestfs-javadoc~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-mount", rpm:"libguestfs-mount~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-libguestfs", rpm:"ocaml-libguestfs~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-libguestfs-devel", rpm:"ocaml-libguestfs-devel~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libguestfs", rpm:"python-libguestfs~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-libguestfs", rpm:"ruby-libguestfs~1.7.17~17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

