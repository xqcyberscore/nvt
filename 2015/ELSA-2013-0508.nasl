# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0508.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123698");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:23 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0508");
script_tag(name: "insight", value: "ELSA-2013-0508 -  sssd security, bug fix and enhancement update - [1.9.2-82] - Resolves: rhbz#888614 - Failure in memberof can lead to failed database update [1.9.2-81] - Resolves: rhbz#903078 - TOCTOU race conditions by copying and removing directory trees [1.9.2-80] - Resolves: rhbz#903078 - Out-of-bounds read flaws in autofs and ssh services responders [1.9.2-79] - Resolves: rhbz#902716 - Rule mismatch isn't noticed before smart refresh on ppc64 and s390x [1.9.2-78] - Resolves: rhbz#896476 - SSSD should warn when pam_pwd_expiration_warning value is higher than passwordWarning LDAP attribute. [1.9.2-77] - Resolves: rhbz#902436 - possible segfault when backend callback is removed [1.9.2-76] - Resolves: rhbz#895132 - Modifications using sss_usermod tool are not reflected in memory cache [1.9.2-75] - Resolves: rhbz#894302 - sssd fails to update to changes on autofs maps [1.9.2-74] - Resolves: rhbz894381 - memory cache is not updated after user is deleted from ldb cache [1.9.2-73] - Resolves: rhbz895615 - ipa-client-automount: autofs failed in s390x and ppc64 platform [1.9.2-72] - Resolves: rhbz#894997 - sssd_be crashes looking up members with groups outside the nesting limit [1.9.2-71] - Resolves: rhbz#895132 - Modifications using sss_usermod tool are not reflected in memory cache [1.9.2-70] - Resolves: rhbz#894428 - wrong filter for autofs maps in sss_cache [1.9.2-69] - Resolves: rhbz#894738 - Failover to ldap_chpass_backup_uri doesn't work [1.9.2-68] - Resolves: rhbz#887961 - AD provider: getgrgid removes nested group memberships [1.9.2-67] - Resolves: rhbz#878583 - IPA Trust does not show secondary groups for AD Users for commands like id and getent [1.9.2-66] - Resolves: rhbz#874579 - sssd caching not working as expected for selinux usermap contexts [1.9.2-65] - Resolves: rhbz#892197 - Incorrect principal searched for in keytab [1.9.2-64] - Resolves: rhbz#891356 - Smart refresh doesn't notice 'defaults' addition with OpenLDAP [1.9.2-63] - Resolves: rhbz#878419 - sss_userdel doesn't remove entries from in-memory cache [1.9.2-62] - Resolves: rhbz#886848 - user id lookup fails for case sensitive users using proxy provider [1.9.2-61] - Resolves: rhbz#890520 - Failover to krb5_backup_kpasswd doesn't work [1.9.2-60] - Resolves: rhbz#874618 - sss_cache: fqdn not accepted [1.9.2-59] - Resolves: rhbz#889182 - crash in memory cache [1.9.2-58] - Resolves: rhbz#889168 - krb5 ticket renewal does not read the renewable tickets from cache [1.9.2-57] - Resolves: rhbz#886091 - Disallow root SSH public key authentication - Add default section to switch statement (Related: rhbz#884666) [1.9.2-56] - Resolves: rhbz#886038 - sssd components seem to mishandle sighup [1.9.2-55] - Resolves: rhbz#888800 - Memory leak in new memcache initgr cleanup function [1.9.2-54] - Resolves: rhbz#888614 - Failure in memberof can lead to failed database update [1.9.2-53] - Resolves: rhbz#885078 - sssd_nss crashes during enumeration if the enumeration is taking too long [1.9.2-52] - Related: rhbz#875851 - sysdb upgrade failed converting db to 0.11 - Include more debugging during the sysdb upgrade [1.9.2-51] - Resolves: rhbz#877972 - ldap_sasl_authid no longer accepts full principal [1.9.2-50] - Resolves: rhbz#870045 - always reread the master map from LDAP - Resolves: rhbz#876531 - sss_cache does not work for automount maps [1.9.2-49] - Resolves: rhbz#884666 - sudo: if first full refresh fails, schedule another first full refresh [1.9.2-48] - Resolves: rhbz#880956 - Primary server status is not always reset after failover to backup server happened - Silence a compilation warning in the memberof plugin (Related: rhbz#877974) - Do not steal resolv result on error (Related: rhbz#882076) [1.9.2-47] - Resolves: rhbz#882923 - Negative cache timeout is not working for proxy provider [1.9.2-46] - Resolves: rhbz#884600 - ldap_chpass_uri failover fails on using same hostname [1.9.2-45] - Resolves: rhbz#858345 - pam_sss(crond:account): Request to sssd failed. Timer expired [1.9.2-44] - Resolves: rhbz#878419 - sss_userdel doesn't remove entries from in-memory cache [1.9.2-43] - Resolves: rhbz#880176 - memberUid required for primary groups to match sudo rule [1.9.2-42] - Resolves: rhbz#885105 - sudo denies access with disabled ldap_sudo_use_host_filter [1.9.2-41] - Resolves: rhbz#883408 - Option ldap_sudo_include_regexp named incorrectly [1.9.2-40] - Resolves: rhbz#880546 - krb5_kpasswd failover doesn't work - Fix the error handler in sss_mc_create_file (Related: #789507) [1.9.2-39] - Resolves: rhbz#882221 - Offline sudo denies access with expired entry_cache_timeout - Fix several bugs found by Coverity and clang: - Check the return value of diff_gid_lists (Related: #869071) - Move misplaced sysdb assignment (Related: #827606) - Remove dead assignment (Related: #827606) - Fix copy-n-paste error in the memberof plugin (Related: #877974) [1.9.2-38] - Resolves: rhbz#882923 - Negative cache timeout is not working for proxy provider - Link sss_ssh_authorizedkeys and sss_ssh_knowhostsproxy with the client libraries (Related: #870060) - Move sss_ssh_knownhosts documentation to the correct section (Related: #870060) [1.9.2-37] - Resolves: rhbz#884480 - user is not removed from group membership during initgroups - Fix incorrect synchronization in mmap cache (Related: #789507) [1.9.2-36] - Resolves: rhbz#883336 - sssd crashes during start if id_provider is not mentioned [1.9.2-35] - Resolves: rhbz#882290 - arithmetic bug in the SSSD causes netgroup midpoint refresh to be always set to 10 seconds [1.9.2-34] - Resolves: rhbz#877974 - updating top-level group does not reflect ghost members correctly - Resolves: rhbz#880159 - delete operation is not implemented for ghost users [1.9.2-33] - Resolves: rhbz#881773 - mmap cache needs update after db changes [1.9.2-32] - Resolves: rhbz#875677 - password expiry warning message doesn't appear during auth - Fix potential NULL dereference when skipping built-in AD groups (Related: rhbz#874616) - Add missing parameter to DEBUG message (Related: rhbz#829742) [1.9.2-31] - Resolves: rhbz#882076 - SSSD crashes when c-ares returns success but an empty hostent during the DNS update - Do not version libsss_sudo, it's not supposed to be linked against, but dlopened (Related: rhbz#761573) [1.9.2-30] - Resolves: rhbz#880140 - sssd hangs at startup with broken configurations [1.9.2-29] - Resolves: rhbz#878420 - SIGSEGV in IPA provider when ldap_sasl_authid is not set [1.9.2-28] - Resolves: rhbz#874616 - Silence the DEBUG messages when ID mapping code skips a built-in group [1.9.2-27] - Resolves: rhbz#824244 - sssd does not warn into sssd.log for broken configurations [1.9.2-26] - Resolves: rhbz#874673 - user id lookup fails using proxy provider - Fix a possibly uninitialized variable in the LDAP provider - Related: rhbz#877130 [1.9.2-25] - Resolves: rhbz#878262 - ipa password auth failing for user principal name when shorter than IPA Realm name - Resolves: rhbz#871843 - Nested groups are not retrieved appropriately from cache [1.9.2-24] - Resolves: rhbz#870238 - IPA client cannot change AD Trusted User password [1.9.2-23] - Resolves: rhbz#877972 - ldap_sasl_authid no longer accepts full principal [1.9.2-22] - Resolves: rhbz#861075 - SSSD_NSS failure to gracefully restart after sbus failure [1.9.2-21] - Resolves: rhbz#877354 - ldap_connection_expire_timeout doesn't expire ldap connections [1.9.2-20] - Related: rhbz#877126 - Bump the release tag [1.9.2-20] - Resolves: rhbz#877126 - subdomains code does not save the proper user/group name [1.9.2-19] - Resolves: rhbz#877130 - LDAP provider fails to save empty groups - Related: rhbz#869466 - check the return value of waitpid() [1.9.2-18] - Resolves: rhbz#870039 - sss_cache says 'Wrong DB version' [1.9.2-17] - Resolves: rhbz#875740 - 'defaults' entry ignored [1.9.2-16] - Resolves: rhbz#875738 - offline authentication failure always returns System Error [1.9.2-15] - Resolves: rhbz#875851 - sysdb upgrade failed converting db to 0.11 [1.9.2-14] - Resolves: rhbz#870278 - ipa client setup should configure host properly in a trust is in place [1.9.2-13] - Resolves: rhbz#871160 - sudo failing for ad trusted user in IPA environment [1.9.2-12] - Resolves: rhbz#870278 - ipa client setup should configure host properly in a trust is in place [1.9.2-11] - Resolves: rhbz#869678 - sssd not granting access for AD trusted user in HBAC rule [1.9.2-10] - Resolves: rhbz#872180 - subdomains: Invalid sub-domain request type - Related: rhbz#867933 - invalidating the memcache with sss_cache doesn't work if the sssd is not running [1.9.2-9] - Resolves: rhbz#873988 - Man page issue to list 'force_timeout' as an option for the [sssd] section [1.9.2-8] - Resolves: rhbz#873032 - Move sss_cache to the main subpackage [1.9.2-7] - Resolves: rhbz#873032 - Move sss_cache to the main subpackage - Resolves: rhbz#829740 - Init script reports complete before sssd is actually working - Resolves: rhbz#869466 - SSSD starts multiple processes due to syntax error in ldap_uri - Resolves: rhbz#870505 - sss_cache: Multiple domains not handled properly - Resolves: rhbz#867933 - invalidating the memcache with sss_cache doesn't work if the sssd is not running - Resolves: rhbz#872110 - User appears twice on looking up a nested group [1.9.2-6] - Resolves: rhbz#871576 - sssd does not resolve group names from AD - Resolves: rhbz#872324 - pam: fd leak when writing the selinux login file in the pam responder - Resolves: rhbz#871424 - authconfig chokes on sssd.conf with chpass_provider directive [1.9.2-5] - Do not send SIGKILL to service right after sending SIGTERM - Resolves: #771975 - Fix the initial sudo smart refresh - Resolves: #869013 - Implement password authentication for users from trusted domains - Resolves: #869071 - LDAP child crashed with a wrong keytab - Resolves: #869150 - The sssd_nss process grows the memory consumption over time - Resolves: #869443 [1.9.2-4] - BuildRequire selinux-policy so that selinux login support is built in - Resolves: #867932 [1.9.2-3] - Do not segfault if namingContexts contain no values or multiple values - Resolves: rhbz#866542 [1.9.2-2] - Fix the 'ca' translation of the sssd-simple manual page - Related: rhbz#827606 - Rebase SSSD to 1.9 in 6.4 [1.9.2-1] - New upstream release 1.9.2 [1.9.1-1] - Rebase to 1.9.1 [1.9.0-3] - Require the latest libldb [1.9.0-2] - Rebase to 1.9.0 - Resolves: rhbz#827606 - Rebase SSSD to 1.9 in 6.4 [1.9.0-1.rc1] - Rebase to 1.9.0 RC1 - Resolves: rhbz#827606 - Rebase SSSD to 1.9 in 6.4 - Bump the selinux-policy version number to pull in required fixes [1.8.0-33] - Resolves: rhbz#840089 - Update the shadowLastChange attribute with days since the Epoch, not seconds"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0508");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0508.html");
script_cve_id("CVE-2013-0219","CVE-2013-0220");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_sudo-devel", rpm:"libsss_sudo-devel~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.9.2~82.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

