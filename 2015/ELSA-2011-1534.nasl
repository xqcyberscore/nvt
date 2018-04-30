# OpenVAS Vulnerability Test
# Description: Oracle Linux Local Check
# $Id: ELSA-2011-1534.nasl 9657 2018-04-27 10:38:29Z cfischer $

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
script_oid("1.3.6.1.4.1.25623.1.0.122043");
script_version("$Revision: 9657 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:07 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-04-27 12:38:29 +0200 (Fri, 27 Apr 2018) $");
script_name("Oracle Linux Local Check: ELSA-2011-1534");
script_tag(name: "insight", value: "ELSA-2011-1534 -  nfs-utils security, bug fix, and enhancement update - [1.2.3-15]- mout.nfs: Don't roll back to IPv4 when IPv6 fails (bz 744657)- rpcdebug: Added pNFS and FSCache debugging (bz 747400)[1.2.3-14]- mount.nfs: Backported how upstream handles the SIGXFSZ signal (bz 697981)[1.2.3-13]- mount.nfs: Reworked the code that deals with RLIMIT_FSIZE (bz 697981)[1.2.3-12]- Removed the stripping of debugging information from rpcdebug (bz 729001)[1.2.3-11]- mount.nfs: Fixed problem in mount error verbosity patch (bz 731693)[1.2.3-10]- mount.nfs: add error verbosity to invalid versions (bz 731693)[1.2.3-9]- umount.nfs: Got IPV6 unmounts working again (bz 732673)- mountd: return multiple hosts exporting the same directory (bz 726112) - mount: Better error message for invalid version (bz 723780)[1.2.3-8]- initscripts: just try to mount rpc_pipefs always (bz 692702) - Rely on crypto module autoloading in init scripts- svcgssd: Document '-n' for svcgssd (bz 697359)- mount.nfs: anticipate RLIMIT_FSIZE (bz 697981)- exportfs manpage: Ipv6 update (bz 715078)- mountd: Stop segfault in mtab code (bz 723438)- exportfs: wildcards in exports can lead to unintended mounts (bz 715391)- umount: allow spaces in unmount paths (bz 702273)- specfile: reordered how libgssglue is linked in (bz 720479)");
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1534");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1534.html");
script_cve_id("CVE-2011-1749","CVE-2011-2500");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.2.3~15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

