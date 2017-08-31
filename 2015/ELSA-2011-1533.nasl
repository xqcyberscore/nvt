# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1533.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122030");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:56 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1533");
script_tag(name: "insight", value: "ELSA-2011-1533 -  ipa security and bug fix update - [2.1.3-9.el6]- Add current password prompt when changing own password in web UI (#751179)- Remove extraneous trailing ' from netgroup patch (#749352)[2.1.3-8.el6]- Updated patch for CVE-2011-3636 to include CR in the HTTP headers. xmlrpc-c in RHEL-6 doesn't suppose the dont_advertise option so that is not set any more. Another fake header, X-Original-User_Agent, is added so there is no more trailing junk after the Referer header. (#749870)[2.1.3-7.el6]- Require an HTTP Referer header to address CSRF attackes. CVE-2011-3636. (#749870)[2.1.3-6.el6]- Users not showing up in nis netgroup triple (#749352)[2.1.3-5.el6]- Add update file to remove entitlement roles, privileges and permissions (#739060)[2.1.3-4.el6]- Quote worker option in krb5kdc (#748754)[2.1.3-3.el6]- hbactest fails while you have svcgroup in hbacrule (#746227)- Add Kerberos domain mapping for system hostname (#747443)- Format certificates as PEM in browser (#701325)[2.1.3-2.el6]- ipa-client-install hangs if the discovered server is unresponsive (#745392)- Fix minor problems in help system (#747028)- Remove help fix from Disable automember patch (#746717)- Update minimum version of sssd to 1.5.1-60 to pick up SELinux fix (#746265)[2.1.3-1.el6]- Update to upstream 2.1.3 release (#736170)- Additional branding (#742264)- Disable automember cli (#746717)- ipa-client-install sometimes fails to start sssd properly (#736954)- ipa-client-install adds duplicate information to krb5.conf (#714597)- ipa-client-install should configure hostname (#714919)- inconsistency in enabling 'delete' buttons (#730751)- hbactest does not resolve canonical names during simulation (#740850)- Default DNS Administration Role - Permissions missing (#742327)- named fails to start after installing ipa server when short (#742875)- Duplicate hostgroup and netgroup should not be allowed (#743253)- named fails to start (#743680)- Global password policy should not be able to be deleted (#744074)- Client install fails when anonymous bind is disabled (#744101)- Internal Server Error adding invalid reverse DNS zone (#744234)- ipa hbactest does not evaluate indirect members from groups. (#744410)- Leaks KDC password and master password via command line arguments (#744422)- Traceback when upgrading from ipa-server-2.1.1-1 (#744798)- IPA User's Primary GID is not being set to their UPG's GID (#745552)- --forwarder option of ipa-dns-install allows invalid IP addr (#745698)- UI does not grant access based on roles (#745957)- Unable to add external user for RunAs User for Sudo (#746056)- Typo in error message while adding invalid ptr record. (#746199)- Don't use python 2.7-only syntax (#746229)- Error when using ipa-client-install with --no-sssd option (#746276)- Installation fails if sssd.conf exists and is already config (#746298)- External hosts are not removed properly from sudorule (#709665)- Competely remove entitlement support (#739060)- Add winsync section to ipa-replica-manage man page (#744306)[2.1.2-2.el6]- Remove python-rhsm as a Requires (#739060)[2.1.2-1.el6]- Update to upstream 2.1.2 release (#736170)- More completely disable entitlement support (#739060)- Drop patch to ignore return value from restorecon (upstreamed)- Set min version of 389-ds-base to 1.2.9.12-2- Set min version of dogtag to 9.0.3-20- Rebased hide-pkinit, ipa-RHEL-index and remove-persistent-search patches (#700586)[2.1.1-4.el6]- Update RHEL patch (#740094)[2.1.1-3.el6]- Ignore return value from restorecon (#739604)- Disable entitlement support (#739060, #739061)[2.1.1-2.el6]- Update minimum xmlrpc-c version (#736787)- Fix package installation order causing SELinux problems (#737516)[2.1.1-1.el6]- Update to upstream 2.1.1 release (#732803)[2.1.0-1.el6]- Resolves: rhbz#708388 - Update to upstream 2.1.0 release[2.0.0-25]- Remove client debug logging patch (#705800)[2.0.0-24]- Wait for 389-ds tasks to complete (#698421)- Set replica to restart ipa on boot (#705794)- Improve client debug logging (#705800)- Managed Entries not configured on replicas (#703869)- Don't create bogus aRecord when creating new zone (#704012)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1533");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1533.html");
script_cve_id("CVE-2011-3636");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~2.1.3~9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~2.1.3~9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~2.1.3~9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~2.1.3~9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~2.1.3~9.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

