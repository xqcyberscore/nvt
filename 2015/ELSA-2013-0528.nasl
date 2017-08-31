# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0528.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123699");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:24 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0528");
script_tag(name: "insight", value: "ELSA-2013-0528 -  ipa security, bug fix and enhancement update - [3.0.0-25.el6] - Filter generated winbind dependencies so the right version of samba can be installed. (#905594) [3.0.0-24.el6] - Add certmonger condrestart to server post scriptlet (#903758) - Make certmonger a (pre) Requires (#903758) - Add selinux-policy to Requires(pre) to avoid post scriptlet AVCs (#903758) - Set minimum version of pki-ca to 9.0.3-30 and add to Requires(pre) to pick up certmonger upgrade fix (#902474) - Update anonymous access ACI to protect secret attributes (#902481) [3.0.0-23.el6] - Installer should not connect to 127.0.0.1. (#895561) - Don't initialize NSS if we don't have to. (#878220) [3.0.0-22.el6] - Set minimum version of bind-dyndb-ldap to 2.3-2 to pick up missing DNS zone SOA serial fix (#894131) - Stopped named service crashed ipa-upgradeconfig program (#895298) - ipa-replica-prepare crashed when manipulating DNS zone without SOA serial (#894143) - Use new certmonger locking to prevent NSS database corruption during CA subsystem renewal (#883484) - Set minimum selinux-policy to 3.7.19-193 to allow certmonger to talk to dbus in an rpm scriptlet. (related #883484) - Set minimum vresion of certmonger to 0.61-3 for new locking scheme (related #883484) [3.0.0-21.el6] - Properly handle migrated uniqueMember attributes (#894090) - ipa permission-find using valid targetgroup throws internal error (#893827) - Fix migration of CRLs to new directory location (#893722) - Installing IPA with a single realm component sometimes fails (#893187) [3.0.0-20.el6] - Set maxbersize to a large value to accomondate large CRLs during replica installation. (#888956) - Set minimum version of pki-ca, pki-slient and pki-setup to 9.0.3-29 to pick up default CA validity period of 20 years. (#891980) [3.0.0-19.el6] - Client installation crashes when Kerberos SRV record is not found (#889583) - Fix typo in patch 0048 for CVE-2012-5484 (#878220) [3.0.0-18.el6] - Cookie Expires date should be locale insensitive to avoid CLI errors (#888915) [3.0.0-17.el6] - ipa delegation-find --group option returns internal error (#888524) - Add missing Requires for python-crypto replacement (#878969) [3.0.0-16.el6] - sssd is not enabled on client/server install (#888124) [3.0.0-15.el6] - ipa-server-install --uninstall doesn't clear certmonger dirs, which leads to install failing (#817080) [3.0.0-14.el6] - Compliant client side session cookie behavior. CVE-2012-5631. (#886371) [3.0.0-13.el6] - Use secure method to retrieve IPA CA during client enrollment. CVE-2012-5484 (#878220) - Reformat patch 0044 so it works with git-am [3.0.0-12.el6] - Include /var/lib/sss/pubconf/krb5.include.d/ for domain-realm mappings in krb5.conf (#883166) - Set minimum selinux-policy >= 3.7.19-184 to allow domains that can read sssd_public_t files to also list the directory (#881413) - Remove dist label from changelog entries. - Fix timestamp on patched files to avoid multilib warnings [3.0.0-11.el6] - Set Requires on httpd 2.2.15-24, mod_nss to 1.0.8-18 and patch to check for existing mod_ssl configuration. These versions allow mod_proxy to simultaneously support SSL servers using mod_ssl and mod_proxy (#761574) - IPA WebUI login for AD Trusted User fails (#875261) - Add 'disable_last_success' and 'disable_lockout' to the ipa_lockout plugin (#824488) [3.0.0-10.el6] - Make default group type POSIX in ui (#880655) - Write replacement for python-crypto (#878969) - ipa trust-add prints misleading information about required DNS setting (#878485) - Lookup user SIDs in external groups (#878480) - Special case NFS related ticket to avoid attaching MS-PACs (#878462) - IPA users are not available after ipa-server-install because sssd not running (#878288) - Incorrect error message when time difference between AD and IPA is too great (#877434) - Missing option to add SSH Public Key in Web UI after upgrade (#877324) [3.0.0-9.el6] - Update minimum BR and Requires of sssd to 1.9.2-25 (related #870278, related #871160, related #878262) - Replication agreement tools report errors with new single instance CA database (#878491) - If time is moved back on the IPA server, ipasam does not invalidate the existing ticket (#866576) [3.0.0-8.el6] - Server installation fails to find A/AAAA record for IPA hostname (#874935) - Out of range error when listing RUV on host with no agreements (#873726) - Tighten dependency on krb5-server to limit to 1.10 (#872707) - Default SELinuxusermaporder needs to mapped with default selinux users list (#870053) - Clarify trust-add help regarding multiple runs against the same domain (#869741) - Improve reliabilityof RA renewal script (#869663) - Add option to disable DNS forwarding by zone (#869658) - Update minimum version of bind-dyndb-ldap to 2.3-1 (#869658) - Improve information on passsync user in man page, command help (#869656) - Resolve external members from trusted domain via Global Catalog (#869616) - Process relative nameserver DNS record correctly (#868956) - ipa-adtrust-install does not reset all information when re-run (#867447) - Fix potential memory leak in KDB backend (#811989) [3.0.0-7.el6] - Fix type conversion of integers when doing modifications (#870446) - Set SECURE_NFS to lowercase yes rather than uppercase (#869654) - Add autofs service to sssd.conf before enabling it (#869649) - Add strict Requires for policycoreutils to avoid user removing them during package lifetime (#869281) - Make internal rename_s() call compatible with python-ldap-2.3.10 (#867902) - Update minimum version of bind-dyndb-ldap to 2.2-1.el6 (related #871583) - Restart httpd after running ipa-adtrust-install (#866966) [3.0.0-6.el6] - Add patch to override xmlrpc request method for session (#786199) - Bad link to Web UI config page after session is expired (#869279) - extdom plugin does not handle Posix UID and GID request (#867676) - ipa-server-install --setup-dns always installs reverse zone (#866978) - Inform user when ipa-upgradeconfig reports errors (#866977) - Certificate request fails when CSR has subjectAltnames (#866955) - ipa-adtrust-install checks for /usr/bin/smbpasswd, which is not required (#866572) - Instructions to uninstall are unclear (#856294) - Inconsistent service naming in ipa-server-install (#856292) - Improve instructions to generate certificate in Web UI (#856282) - /etc/ipa/default.conf is out of date (#855855) - Time synchronization is disabled in ipa-client-install (#854325) - ipa-replica-install httpd restart sometimes fails (#845405) - Improve error messages during ipa-replica-manage del (#835632) - Always log errors from dogtag (#813401) [3.0.0-5.el6] - Update to upstream 3.0.0 GA release (#827602) - Add zip dependency, needed for creating unsigned Firefox extensions - Filter generated winbind dependencies so the right version of samba can be installed. - Remove patch to support python-ldap 2.3.10. Fixed upstream. - Add directory /var/lib/ipa/pki-ca/publish for CRL published by pki-ca (#864533) - Add zip dependency, needed for creating unsigned Firefox extensions [3.0.0-4.el6] - Make sure server-trust-ad subpackage alternates winbind_krb5_locator.so plugin to /dev/null since they cannot be used when trusts are configured (related #864889) - Update BR and Requires of samba4 to 4.0.0-31 to pick up winbind_krb5_locator alternatives change. (related #864889) [3.0.0-3.el6] - Update to upstream 3.0.0.rc2 release (#827602) - Provide new Firefox extension. - Own /etc/ipa/ca.crt [3.0.0-2.el6] - Remove Requires on krb5-pkinit-openssl as part of disabling pkinit code. - Add missing subdirectories in site-packages/ipaserver discovered by rpmdiff. (#827602) [3.0.0-1.el6] - Update to upstream 3.0.0.rc1 release (#827602) - Update BR and Requires of 389-ds-base to 1.2.11.14 - Update BR and Requires of krb5 to 1.10 - Update BR and Requires of samba4 to 4.0.0-24 - Update BR and Requires of sssd to 1.9.0 - Update Requires on policycoreutils to 2.0.83-19.24 - Update Requires on httpd to httpd-2.2.15-17 to pick up #787247 - Update minimum version of bind-dyndb-ldap to 1.1.0-0.9.b1.el6_3.1 - Update minimum version of bind to 9.8.2-0.10.rc1.el6_3.2 - Sync upstream spec file Requires - Add patch to support python-ldap 2.3.10"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0528");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0528.html");
script_cve_id("CVE-2012-4546");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~25.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

