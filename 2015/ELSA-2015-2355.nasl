# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2355.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122786");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-25 13:18:52 +0200 (Wed, 25 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2355");
script_tag(name: "insight", value: "ELSA-2015-2355 -  sssd security, bug fix, and enhancement update - [1.13.0-40]- Resolves: rhbz#1270827 - local overrides: don't contact server with overridden name/id[1.13.0-39]- Resolves: rhbz#1267837 - sssd_be crashed in ipa_srv_ad_acct_lookup_step[1.13.0-38]- Resolves: rhbz#1267176 - Memory leak / possible DoS with krb auth.[1.13.0-37]- Resolves: rhbz#1267836 - PAM responder crashed if user was not set[1.13.0-36]- Resolves: rhbz#1266107 - AD: Conditional jump or move depends on uninitialised value[1.13.0-35]- Resolves: rhbz#1250135 - Detect re-established trusts in the IPA subdomain code[1.13.0-34]- Fix a Coverity warning in dyndns code- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead of processing other commands[1.13.0-33]- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead of processing other commands[1.13.0-32]- Resolves: rhbz#1263735 - Could not resolve AD user from root domain[1.13.0-31]- Remove -d from sss_override manpage- Related: rhbz#1259512 - sss_override : The local override user is not found[1.13.0-30]- Patches required for better handling of failover with one-way trusts- Related: rhbz#1250135 - Detect re-established trusts in the IPA subdomain code[1.13.0-29]- Resolves: rhbz#1263587 - sss_override --name doesn't work with RFC2307 and ghost users[1.13.0-28]- Resolves: rhbz#1259512 - sss_override : The local override user is not found[1.13.0-27]- Resolves: rhbz#1260027 - sssd_be memory leak with sssd-ad in GPO code[1.13.0-26]- Resolves: rhbz#1256398 - sssd cannot resolve user names containing backslash with ldap provider[1.13.0-25]- Resolves: rhbz#1254189 - sss_override contains an extra parameter --debug but is not listed in the man page or in the arguments help[1.13.0-24]- Resolves: rhbz#1254518 - Fix crash in nss responder[1.13.0-23]- Support import/export for local overrides- Support FQDNs for local overrides- Resolves: rhbz#1254184 - sss_override does not work correctly when 'use_fully_qualified_names = True'[1.13.0-22]- Resolves: rhbz#1244950 - Add index for 'objectSIDString' and maybe to other cache attributes[1.13.0-21]- Resolves: rhbz#1250415 - sssd: p11_child hardening[1.13.0-20]- Related: rhbz#1250135 - Detect re-established trusts in the IPA subdomain code[1.13.0-19]- Resolves: rhbz#1202724 - [RFE] Add a way to lookup users based on CAC identity certificates[1.13.0-18]- Resolves: rhbz#1232950 - [IPA/IdM] sudoOrder not honored as expected[1.13.0-17]- Fix wildcard_limit=0- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface[1.13.0-16]- Fix race condition in invalidating the memory cache- Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups[1.13.0-15]- Resolves: rhbz#1249015 - KDC proxy not working with SSSD krb5_use_kdcinfo enabled[1.13.0-14]- Bump release number- Related: rhbz#1246489 - sss_obfuscate fails with 'ImportError: No module named pysss'[1.13.0-13]- Fix missing dependency of sssd-tools- Resolves: rhbz#1246489 - sss_obfuscate fails with 'ImportError: No module named pysss'[1.13.0-12]- More memory cache related fixes- Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups[1.13.0-11]- Remove binary blob from SC patches as patch(1) can't handle those- Related: rhbz#854396 - [RFE] Support for smart cards[1.13.0-10]- Resolves: rhbz#1244949 - getgrgid for user's UID on a trust client prevents getpw*[1.13.0-9]- Fix memory cache integration tests- Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups- Resolves: rhbz#854396 - [RFE] Support for smart cards[1.13.0-8]- Remove OTP from PAM stack correctly- Related: rhbz#1200873 - [RFE] Allow smart multi step prompting when user logs in with password and token code from IPA- Handle sssd-owned keytabs when sssd runs as root- Related: rhbz#1205144 - RFE: Support one-way trusts for IPA[1.13.0-7]- Resolves: rhbz#1183747 - [FEAT] UID and GID mapping on individual clients[1.13.0-6]- Resolves: rhbz#1206565 - [RFE] Add dualstack and multihomed support- Resolves: rhbz#1187146 - If v4 address exists, will not create nonexistant v6 in ipa domain[1.13.0-5]- Resolves: rhbz#1242942 - well-known SID check is broken for NetBIOS prefixes[1.13.0-4]- Resolves: rhbz#1234722 - sssd ad provider fails to start in rhel7.2[1.13.0-3]- Add support for InfoPipe wildcard requests- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface[1.13.0-2]- Also package the initgr memcache- Related: rhbz#1205554 - Rebase SSSD to 1.13.x[1.13.0-1]- Rebase to 1.13.0 upstream- Related: rhbz#1205554 - Rebase SSSD to 1.13.x- Resolves: rhbz#910187 - [RFE] authenticate against cache in SSSD- Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups[1.13.0.3alpha]- Don't default to SSSD user- Related: rhbz#1205554 - Rebase SSSD to 1.13.x[1.13.0.2alpha]- Related: rhbz#1205554 - Rebase SSSD to 1.13.x- GPO default should be permissve[1.13.0.1alpha]- Resolves: rhbz#1205554 - Rebase SSSD to 1.13.x- Relax the libldb requirement- Resolves: rhbz#1221992 - sssd_be segfault at 0 ip sp error 6 in libtevent.so.0.9.21- Resolves: rhbz#1221839 - SSSD group enumeration inconsistent due to binary SIDs- Resolves: rhbz#1219285 - Unable to resolve group memberships for AD users when using sssd-1.12.2-58.el7_1.6.x86_64 client in combination with ipa-server-3.0.0-42.el6.x86_64 with AD Trust- Resolves: rhbz#1217559 - [RFE] Support GPOs from different domain controllers- Resolves: rhbz#1217350 - ignore_group_members doesn't work for subdomains- Resolves: rhbz#1217127 - Override for IPA users with login does not list user all groups- Resolves: rhbz#1216285 - autofs provider fails when default_domain_suffix and use_fully_qualified_names set- Resolves: rhbz#1214719 - Group resolution is inconsistent with group overrides- Resolves: rhbz#1214718 - Overridde with --login fails trusted adusers group membership resolution- Resolves: rhbz#1214716 - idoverridegroup for ipa group with --group-name does not work- Resolves: rhbz#1214337 - Overrides with --login work in second attempt- Resolves: rhbz#1212489 - Disable the cleanup task by default- Resolves: rhbz#1211830 - external users do not resolve with 'default_domain_suffix' set in IPA server sssd.conf- Resolves: rhbz#1210854 - Only set the selinux context if the context differs from the local one- Resolves: rhbz#1209483 - When using id_provider=proxy with auth_provider=ldap, it does not work as expected- Resolves: rhbz#1209374 - Man sssd-ad(5) lists Group Policy Management Editor naming for some policies but not for all- Resolves: rhbz#1208507 - sysdb sudo search doesn't escape special characters- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface- Resolves: rhbz#1206566 - SSSD does not update Dynamic DNS records if the IPA domain differs from machine hostname's domain- Resolves: rhbz#1206189 - [bug] sssd always appends default_domain_suffix when checking for host keys- Resolves: rhbz#1204203 - sssd crashes intermittently- Resolves: rhbz#1203945 - [FJ7.0 Bug]: getgrent returns error because sss is written in nsswitch.conf as default- Resolves: rhbz#1203642 - GPO access control looks for computer object in user's domain only- Resolves: rhbz#1202245 - SSSD's HBAC processing is not permissive enough with broken replication entries- Resolves: rhbz#1201271 - sssd_nss segfaults if initgroups request is by UPN and doesn't find anything- Resolves: rhbz#1200873 - [RFE] Allow smart multi step prompting when user logs in with password and token code from IPA- Resolves: rhbz#1199541 - Read and use the TTL value when resolving a SRV query- Resolves: rhbz#1199533 - [RFE] Implement background refresh for users, groups or other cache objects- Resolves: rhbz#1199445 - Does sssd-ad use the most suitable attribute for group name?- Resolves: rhbz#1198477 - ccname_file_dummy is not unlinked on error- Resolves: rhbz#1187103 - [RFE] User's home directories are not taken from AD when there is an IPA trust with AD- Resolves: rhbz#1185536 - In ipa-ad trust, with 'default_domain_suffix' set to AD domain, IPA user are not able to log unless use_fully_qualified_names is set- Resolves: rhbz#1175760 - [RFE] Have OpenLDAP lock out ssh keys when account naturally expires- Resolves: rhbz#1163806 - [RFE]ad provider dns_discovery_domain option: kerberos discovery is not using this option- Resolves: rhbz#1205160 - Complain loudly if backend doesn't start due to missing or invalid keytab[1.12.2-61]- Resolves: rhbz#1226119 - Properly handle AD's binary objectGUID[1.12.2-60]- Filter out domain-local groups during AD initgroups operation- Related: rhbz#1201840 - SSSD downloads too much information when fetching information about groups[1.12.2-59]- Resolves: rhbz#1201840 - SSSD downloads too much information when fetching information about groups"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2355");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2355.html");
script_cve_id("CVE-2015-5292");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libipa_hbac", rpm:"python-libipa_hbac~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libsss_nss_idmap", rpm:"python-libsss_nss_idmap~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-sss", rpm:"python-sss~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-sss-murmur", rpm:"python-sss-murmur~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-libwbclient", rpm:"sssd-libwbclient~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-libwbclient-devel", rpm:"sssd-libwbclient-devel~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.13.0~40.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

