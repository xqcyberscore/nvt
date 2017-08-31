# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0640.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122643");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:50:01 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0640");
script_tag(name: "insight", value: "ELSA-2007-0640 -  conga security, bug fix, and enhancement update - [0.10.0-6.el5.0.1]- Replaced Redhat copyrighted and trademarked images in the conga-0.10.0 tarball.[0.10.0-6]- Fixed bz253783- Fixed bz253914 (conga doesn't allow you to reuse nfs export and nfs client resources)- Fixed bz254038 (Impossible to set many valid quorum disk configurations via conga)- Fixed bz253994 (Cannot specify multicast address for a cluster)- Resolves: bz253783, bz253914, bz254038, bz253994[0.10.0-5]- Fixed bz249291 (delete node task fails to do all items listed in the help document)- Fixed bz253341 (failure to start cluster service which had been modifed for correction)- Related: bz253341- Resolves: bz249291[0.10.0-4]- Fixed bz230451 (fence_xvm.key file is not automatically created. Should have a least a default)- Fixed bz249097 (allow a space as a valid password char)- Fixed bz250834 (ZeroDivisionError when attempting to click an empty lvm volume group)- Fixed bz250443 (storage name warning utility produces a storm of warnings which can lock your browser)- Resolves: bz249097, bz250443, bz250834- Related: bz230451[0.10.0-3]- Fixed bz245947 (luci/Conga cluster configuration tool not initializing cluster node members)- Fixed bz249641 (conga is unable to do storage operations if there is an lvm snapshot present)- Fixed bz249342 (unknown ricci error when adding new node to cluster)- Fixed bz249291 (delete node task fails to do all items listed in the help document)- Fixed bz249091 (RFE: tell user they are about to kill all their nodes)- Fixed bz249066 (AttributeError when attempting to configure a fence device)- Fixed bz249086 (Unable to add a new fence device to cluster)- Fixed bz249868 (Use of failover domain not correctly shown)- Resolves bz245947, bz249641, bz249342, bz249291, bz249091,- Resolves bz249066, bz249086, bz249868- Related: bz249351[0.10.0-2]- Fixed bz245202 (Conga needs to support Internet Explorer 6.0 and later)- Fixed bz248317 (luci sets incorrect permissions on /usr/lib64/luci and /var/lib/luci) - Resolves: bz245202 bz248317[0.10.0-1]- Fixed bz238655 (conga does not set the 'nodename' attribute for manual fencing)- Fixed bz221899 (Node log displayed in partially random order)- Fixed bz225782 (Need more luci service information on startup - no info written to log about failed start cause)- Fixed bz227743 (Intermittent/recurring problem - when cluster is deleted, sometimes a node is not affected)- Fixed bz227682 (saslauthd[2274]: Deprecated pam_stack module called from service 'ricci')- Fixed bz238726 (Conga provides no way to remove a dead node from a cluster)- Fixed bz239389 (conga cluster: make 'enable shared storage' the default)- Fixed bz239596- Fixed bz240034 (rpm verify fails on luci)- Fixed bz240361 (Conga storage UI front-end is too slow rendering storage)- Fixed bz241415 (Installation using Conga shows 'error' in message during reboot cycle.)- Fixed bz241418 (Conga tries to configurage cluster snaps, though they are not available.)- Fixed bz241706 (Eliminate confusion in add fence flow)- Fixed bz241727 (can't set user permissions in luci)- Fixed bz242668 (luci init script can return non-LSB-compliant return codes)- Fixed bz243701 (ricci init script can exit with non-LSB-compliant return codes)- Fixed bz244146 (Add port number to message when ricci is not started/firewalled on cluster nodes.)- Fixed bz244878 (Successful login results in an infinite redirection loop with MSIE)- Fixed bz239388 (conga storage: default VG creation should be clustered if a cluster node)- Fixed bz239327 (Online User Manual needs modification)- Fixed bz227852 (Lack of debugging information in logs - support issue)- Fixed bz245025 (Conga does not accept '&amp;' character in password field for Fence configuration)- Fixed bz225588 (luci web app does not enforce selection of fence port)- Fixed bz212022 (cannot create cluster using ip addresses)- Fixed bz223162 (Error trying to create a new fence device for a cluster node)- Upgraded to the latest Plone (2.5.3)- Added a 'reprobe storage' button that invalidates cached storage reports and forces a new probe.- Resolves: bz238655, bz221899, bz225782, bz227682, bz227743, bz239389,- Resolves: bz239596, bz240034, bz240361, bz241415, bz241418, bz241706,- Resolves: bz241727, bz242668, bz243701, bz244146, bz244878, bz238726,- Resolves: bz239388, bz239327, bz227852, bz245025, bz225588, bz212022"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0640");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0640.html");
script_cve_id("CVE-2007-4136");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"luci", rpm:"luci~0.10.0~6.el5.0.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.10.0~6.el5.0.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

