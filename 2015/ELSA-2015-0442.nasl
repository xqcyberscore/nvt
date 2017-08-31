# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0442.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123168");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:14 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0442");
script_tag(name: "insight", value: "ELSA-2015-0442 -  ipa security, bug fix, and enhancement update - [4.1.0-18.0.1]- Replace login-screen-logo.png [20362818]- Drop subscription-manager requires for OL7- Drop redhat-access-plugin-ipa requires for OL7- Blank out header-logo.png product-name.png[4.1.0-18]- Fix ipa-pwd-extop global configuration caching (#1187342)- group-detach does not add correct objectclasses (#1187540)[4.1.0-17]- Wrong directories created on full restore (#1186398)- ipa-restore crashes if replica is unreachable (#1186396)- idoverrideuser-add option --sshpubkey does not work (#1185410)[4.1.0-16]- PassSync does not sync passwords due to missing ACIs (#1181093)- ipa-replica-manage list does not list synced domain (#1181010)- Do not assume certmonger is running in httpinstance (#1181767)- ipa-replica-manage disconnect fails without password (#1183279)- Put LDIF files to their original location in ipa-restore (#1175277)- DUA profile not available anonymously (#1184149)- IPA replica missing data after master upgraded (#1176995)[4.1.0-15]- Re-add accidentally removed patches for #1170695 and #1164896[4.1.0-14]- IPA Replicate creation fails with error 'Update failed! Status: [10 Total update abortedLDAP error: Referral]' (#1166265)- running ipa-server-install --setup-dns results in a crash (#1072502)- DNS zones are not migrated into forward zones if 4.0+ replica is added (#1175384)- gid is overridden by uid in default trust view (#1168904)- When migrating warn user if compat is enabled (#1177133)- Clean up debug log for trust-add (#1168376)- No error message thrown on restore(full kind) on replica from full backup taken on master (#1175287)- ipa-restore proceed even IPA not configured (#1175326)- Data replication not working as expected after data restore from full backup (#1175277)- IPA externally signed CA cert expiration warning missing from log (#1178128)- ipa-upgradeconfig fails in CA-less installs (#1181767)- IPA certs fail to autorenew simultaneouly (#1173207)- More validation required on ipa-restore's options (#1176034)[4.1.0-13]- Expand the token auth/sync windows (#919228)- Access is not rejected for disabled domain (#1172598)- krb5kdc crash in ldap_pvt_search (#1170695)- RHEL7.1 IPA server httpd avc denials after upgrade (#1164896)[4.1.0-12]- RHEL7.1 ipa-cacert-manage renewed certificate from MS ADCS not compatible (#1169591)- CLI doesn't show SSHFP records with SHA256 added via nsupdate (regression) (#1172578)[4.1.0-11]- Throw zonemgr error message before installation proceeds (#1163849)- Winsync: Setup is broken due to incorrect import of certificate (#1169867)- Enable last token deletion when password auth type is configured (#919228)- ipa-otp-lasttoken loads all user's tokens on every mod/del (#1166641)- add --hosts and --hostgroup options to allow/retrieve keytab methods (#1007367)- Extend host-show to add the view attribute in set of default attributes (#1168916)- Prefer TCP connections to UDP in krb5 clients (#919228)- [WebUI] Not able to unprovisioning service in IPA 4.1 (#1168214)- webui: increase notification duration (#1171089)- RHEL7.1 ipa automatic CA cert renewal stuck in submitting state (#1166931)- RHEL7.1 ipa-cacert-manage cannot change external to self-signed ca cert (#1170003)- Improve validation of --instance and --backend options in ipa-restore (#951581)- RHEL7.1 ipa replica unable to replicate to rhel6 master (#1167964)- Disable TLS 1.2 in nss.conf until mod_nss supports it (#1156466)[4.1.0-10]- Use NSS protocol range API to set available TLS protocols (#1156466)[4.1.0-9]- schema update on RHEL-6.6 using latest copy-schema-to-ca.py from RHEL-7.1 build fails (#1167196)- Investigate & fix Coverity defects in IPA DS/KDC plugins (#1160756)- 'ipa trust-add ... ' cmd says : (Trust status: Established and verified) while in the logs we see 'WERR_ACCESS_DENIED' during verification step. (#1144121)- POODLE: force using safe ciphers (non-SSLv3) in IPA client and server (#1156466)- Add support/hooks for a one-time password system like SecureID in IPA (#919228)- Tracebacks with latest build for --zonemgr cli option (#1167270)- ID Views: Support migration from the sync solution to the trust solution (#891984)[4.1.0-8]- Improve otptoken help messages (#919228)- Ensure users exist when assigning tokens to them (#919228)- Enable QR code display by default in otptoken-add (#919228)- Show warning instead of error if CA did not start (#1158410)- CVE-2014-7850 freeipa: XSS flaw can be used to escalate privileges (#1165774)- Traceback when adding zone with long name (#1164859)- Backup & Restore mechanism (#951581)- ignoring user attributes in migrate-ds does not work if uppercase characters are returned by ldap (#1159816)- Allow ipa-getkeytab to optionally fetch existing keys (#1007367)- Failure when installing on dual stacked system with external ca (#1128380)- ipa-server should keep backup of CS.cfg (#1059135)- Tracebacks with latest build for --zonemgr cli option (#1167270)- webui: use domain name instead of domain SID in idrange adder dialog (#891984)- webui: normalize idview tab labels (#891984)[4.1.0-7]- ipa-csreplica-manage connect fails (#1157735)- error message which is not understandable when IDNA2003 characters are present in --zonemgr (#1163849)- Fix warning message should not contain CLI commands (#1114013)- Renewing the CA signing certificate does not extend its validity period end (#1163498)- RHEL7.1 ipa-server-install --uninstall Could not set SELinux booleans for httpd (#1159330)[4.1.0-6]- Fix: DNS installer adds invalid zonemgr email (#1056202)- ipaplatform: Use the dirsrv service, not target (#951581)- Fix: DNS policy upgrade raises asertion error (#1161128)- Fix upgrade referint plugin (#1161128)- Upgrade: fix trusts objectclass violationi (#1161128)- group-add doesn't accept gid parameter (#1149124)[4.1.0-5]- Update slapi-nis dependency to pull 0.54-2 (#891984)- ipa-restore: Don't crash if AD trust is not installed (#951581)- Prohibit setting --rid-base for ranges of ipa-trust-ad-posix type (#1138791)- Trust setting not restored for CA cert with ipa-restore command (#1159011)- ipa-server-install fails when restarting named (#1162340)[4.1.0-4]- Update Requires on pki-ca to 10.1.2-4 (#1129558)- build: increase java stack size for all arches- Add ipaSshPubkey and gidNumber to the ACI to read ID user overrides (#891984)- Fix dns zonemgr validation regression (#1056202)- Handle profile changes in dogtag-ipa-ca-renew-agent (#886645)- Do not wait for new CA certificate to appear in LDAP in ipa-certupdate (#886645)- Add bind-dyndb-ldap working dir to IPA specfile- Fail if certmonger can't see new CA certificate in LDAP in ipa-cacert-manage (#886645)- Investigate & fix Coverity defects in IPA DS/KDC plugins (#1160756)- Deadlock in schema compat plugin (#1161131)- ipactl stop should stop dirsrv last (#1161129)- Upgrade 3.3.5 to 4.1 failed (#1161128)- CVE-2014-7828 freeipa: password not required when OTP in use (#1160877)[4.1.0-3]- Do not check if port 8443 is available in step 2 of external CA install (#1129481)[4.1.0-2]- Update Requires on selinux-policy to 3.13.1-4[4.1.0-1]- Update to upstream 4.1.0 (#1109726)[4.1.0-0.1.alpha1]- Update to upstream 4.1.0 Alpha 1 (#1109726)[4.0.3-3]- Add redhat-access-plugin-ipa dependency[4.0.3-2]- Re-enable otptoken_yubikey plugin[4.0.3-1]- Update to upstream 4.0.3 (#1109726)[3.3.3-29]- Server installation fails using external signed certificates with 'IndexError: list index out of range' (#1111320)- Add rhino to BuildRequires to fix Web UI build error"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0442");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0442.html");
script_cve_id("CVE-2010-5312","CVE-2012-6662");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.1.0~18.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.1.0~18.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~4.1.0~18.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.1.0~18.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.1.0~18.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

