# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0310.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123963");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:54 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0310");
script_tag(name: "insight", value: "ELSA-2012-0310 -  nfs-utils security, bug fix, and enhancement update - [1.0.9-60.0.1.el5]- Add support for resvport for unmonting [orabug 13567018][1.0.9-60]- Updated idmapd.conf and idmapd.conf.man to reflect the static user name mapping (502707)- Fixed an umount regression introduced by bz 513094 (bz 781931)[1.0.9-59]- gss: turned of even more excessive syslogs (bz 593097)- mount.nfs: Ignored the SIGXFSZ when handling RLIMIT_FSIZE changes (bz 697979)[1.0.9-58]- gss: turned off more excessive syslogs (bz 593097)- initfiles: more initscripts improvements (bz 710020)- specfile: correct typo when nfsnobodys gid already exists (bz 729603)[1.0.9-57]- Mount fails to anticipate RLIMIT_FSIZE (bz 697979,CVE-2011-1749)[1.0.9-56]- Removed sim crash support (bz 600497)- initfiles: more initscripts improvements (bz 710020)- mount: Don't wait for TCP to timeout twice (bz 736677)[1.0.9-55]- mount: fixed the -o retry option to retry the given amount (bz 736677)- manpage: removed the -o fsc option (bz 715523)- nfsstat: show v4 mounts with -m flag (bz 712438)- mount: allow insecure ports with mounts (bz 513094)- gss: turned off excessive syslogs (bz 593097)- mountd: allow v2 and v3 to be disabled (bz 529588)- specfile: make sure nfsnobodys gid changes when it exists (bz 729603)- initfiles: initscripts improvements (bz 710020)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0310");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0310.html");
script_cve_id("CVE-2011-1749");
script_tag(name:"cvss_base", value:"3.3");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.0.9~60.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

