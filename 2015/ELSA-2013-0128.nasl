# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0128.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123762");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:11 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0128");
script_tag(name: "insight", value: "ELSA-2013-0128 -  conga security, bug fix, and enhancement update - [0.12.2-64.0.2.el5] - Remove conga-enterprise.patch [0.12.2-64.0.1.el5] - Added conga-enterprise.patch - Added conga-enterprise-Carthage.patch to support OEL5 - Replaced redhat logo image in conga-0.12.2.tar.gz and Data.fs [0.12.2-64] - Improvements for bz786372 (Better protect luci's authentication cookie) - Improvements for bz607179 (Improper handling of session timeouts) [0.12.2-60] - Improvements for bz832185 (Luci cannot configure the 'identity_file' attribute for fence_ilo_mp) - Improvements for bz822633 (Add luci support for nfsrestart) [0.12.2-59] - Fix bz835649 (luci uninstall will leave /var/lib/luci/var/pts and /usr/lib*/luci/zope/var/pts behind) [0.12.2-58] - Fix bz832183 (Luci is missing configuration of ssl for fence_ilo) [0.12.2-57] - Fix bz835649 (luci uninstall will leave /var/lib/luci/var/pts and /usr/lib*/luci/zope/var/pts behind) [0.12.2-56] - Fix bz842865 (Conga unable to find/install packages due to line breaks in yum output) [0.12.2-55] - Add support for IBM iPDU fencing configuration (Resolves bz741986) [0.12.2-54] - Fix bz839732 (Conga Add a Service Screen is Missing Option for Restart-Disable Recovery Policy) [0.12.2-53] - Fix bz786372 (Better protect luci's authentication cookie) - Fix bz607179 (Improper handling of session timeouts) [0.12.2-52] - Fix bz822633 (Add luci support for nfsrestart) - Fix bz832181 (fence_apc_snmp is missing from luci) - Fix bz832183 (Luci is missing configuration of ssl for fence_ilo) - Fix bz832185 (Luci cannot configure the 'identity_file' attribute for fence_ilo_mp)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0128");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0128.html");
script_cve_id("CVE-2012-3359");
script_tag(name:"cvss_base", value:"3.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"luci", rpm:"luci~0.12.2~64.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.12.2~64.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

