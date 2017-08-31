# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2154.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122742");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:19 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2154");
script_tag(name: "insight", value: "ELSA-2015-2154 -  krb5 security, bug fix, and enhancement update - [1.13.2-9]- Add patch and test case for 'KDC does not return proper client principal for client referrals'- Resolves: #1259846[1.13.2-9]- Ammend patch for RedHat bug #1252454 ('testsuite complains 'Lifetime has increased by 32436 sec while 0 sec passed!', while rhel5-libkrb5 passes') to handle the newly introduced valgrind hits.[1.13.2-8]- Add a patch to fix RH Bug #1250154 ('[s390x, ppc64, ppc64le]: kadmind does not accept ACL if kadm5.acl does not end with EOL') The code 'accidently' works on x86/AMD64 because declaring a variable or char or results in an or unsigned char or by default while most other platforms (e.g. { s390x, ppc64, ppc64le, ...}) default to or signed char or (still have to use lint(1) to clean up 38 more instances of this kind of bug).[1.13.2-7]- Obsolete multilib versions of server packages to fix RH bug #1251913 ('krb5 should obsolete the multilib versions of krb5-server and krb5-server-ldap'). The following packages are declared obsolete: - krb5-server-1.11.3-49.el7.i686 - krb5-server-1.11.3-49.el7.ppc - krb5-server-1.11.3-49.el7.s390 - krb5-server-ldap-1.11.3-49.el7.i686 - krb5-server-ldap-1.11.3-49.el7.ppc - krb5-server-ldap-1.11.3-49.el7.s390[1.13.2-6]- Add a patch to fix RedHat bug #1252454 ('testsuite complains 'Lifetime has increased by 32436 sec while 0 sec passed!', while rhel5-libkrb5 passes') so that krb5 resolves GSS creds if or time_rec or is requested.[1.13.2-5]- Add a patch to fix RedHat bug #1251586 ('KDC sends multiple requests to ipa-otpd for the same authentication') which causes the KDC to send multiple retries to ipa-otpd for TCP transports while it should only be done for UDP.[1.13.2-4]- the rebase to krb5 1.13.2 in vers 1.13.2-0 also fixed: - Redhat Bug #1247761 ('RFE: Minor krb5 spec file cleanup and sync with recent Fedora 22/23 changes') - Redhat Bug #1247751 ('krb5-config returns wrong -specs path') - Redhat Bug #1247608 ('Add support for multi-hop preauth mechs via or KDC_ERR_MORE_PREAUTH_DATA_REQUIRED or for RFC 6113 ('A Generalized Framework for Kerberos Pre-Authentication')')- Removed 'krb5-1.10-kprop-mktemp.patch' and 'krb5-1.3.4-send-pr-tempfile.patch', both are no longer used since the rebase to krb5 1.13.1[1.13.2-3]- Add patch to fix Redhat Bug #1222903 ('[SELinux] AVC denials may appear when kadmind starts'). The issue was caused by an unneeded or htons() or which triggered SELinux AVC denials due to the 'random' port usage.[1.13.2-2]- Add fix for RedHat Bug #1164304 ('Upstream unit tests loads the installed shared libraries instead the ones from the build')[1.13.2-1]- the rebase to krb5 1.13.1 in vers 1.13.1-0 also fixed: - Bug 1144498 ('Fix the race condition in the libkrb5 replay cache') - Bug 1163402 ('kdb5_ldap_util view_policy does not shows ticket flags on s390x and ppc64') - Bug 1185770 ('Missing upstream test in krb5-1.12.2: src/tests/gssapi/t_invalid.c') - Bug 1204211 ('CVE-2014-5355 krb5: unauthenticated denial of service in recvauth_common() and other')[1.13.2-0]- Update to krb5-1.13.2 - drop patch for krb5-1.13.2-CVE_2015_2694_requires_preauth_bypass_in_PKINIT_enabled_KDC, fixed in krb5-1.13.2 - drop patch for krb5-1.12.1-CVE_2014_5355_fix_krb5_read_message_handling, fixed in krb5-1.13.2[1.13.1-2]- the rebase to krb5 1.13.1 in vers 1.13.1-0 also fixed RH bug #1156144 ('krb5 upstream test t_kdb.py failure')[1.13.1-1]- fix for CVE-2015-2694 (#1218020) 'requires_preauth bypass in PKINIT-enabled KDC'. In MIT krb5 1.12 and later, when the KDC is configured with PKINIT support, an unauthenticated remote attacker can bypass the requires_preauth flag on a client principal and obtain a ciphertext encrypted in the principal's long-term key. This ciphertext could be used to conduct an off-line dictionary attack against the user's password.[1.13.1-0]- Update to krb5-1.13.1 - patch krb5-1.12-selinux-label was updated and renamed to krb5-1.13-selinux-label - patch krb5-1.11-dirsrv-accountlock was updated and renamed to krb5-1.13-dirsrv-accountlock - drop patch for krb5-1.12-pwdch-fast, fixed in krb5-1.13 - drop patch for krb5-1.12ish-kpasswd_tcp, fixed in krb5-1.13 - drop patch for krb5-master-rcache-internal-const, no longer needed - drop patch for krb5-master-rcache-acquirecred-cleanup, no longer needed - drop patch for krb5-master-rcache-acquirecred-source, no longer needed - drop patch for krb5-master-rcache-acquirecred-test, no longer needed - drop patch for krb5-master-move-otp-sockets, no longer needed - drop patch for krb5-master-mechd, no longer needed - drop patch for krb5-master-strdupcheck, no longer needed - drop patch for krb5-master-compatible-keys, no longer needed - drop patch for krb5-1.12-system-exts, fixed in krb5-1.13 - drop patch for 0001-In-ksu-merge-krb5_ccache_copy-and-_restricted, no longer needed - drop patch for 0002-In-ksu-don-t-stat-not-on-disk-ccache-residuals, no longer needed - drop patch for 0003-Use-an-intermediate-memory-cache-in-ksu, no longer needed - drop patch for 0004-Make-ksu-respect-the-default_ccache_name-setting, no longer needed - drop patch for 0005-Copy-config-entries-to-the-ksu-target-ccache, no longer needed - drop patch for 0006-Use-more-randomness-for-ksu-secondary-cache-names, no longer needed - drop patch for 0007-Make-krb5_cc_new_unique-create-DIR-directories, no longer needed - drop patch for krb5-1.12-kpasswd-skip-address-check, fixed in krb5-1.13 - drop patch for 0000-Refactor-cm-functions-in-sendto_kdc.c, no longer needed - drop patch for 0001-Simplify-sendto_kdc.c, no longer needed - drop patch for 0002-Add-helper-to-determine-if-a-KDC-is-the-master, no longer needed - drop patch for 0003-Use-k5_transport-_strategy-enums-for-k5_sendto, no longer needed - drop patch for 0004-Build-support-for-TLS-used-by-HTTPS-proxy-support, no longer needed - drop patch for 0005-Add-ASN.1-codec-for-KKDCP-s-KDC-PROXY-MESSAGE, no longer needed - drop patch for 0006-Dispatch-style-protocol-switching-for-transport, no longer needed - drop patch for 0007-HTTPS-transport-Microsoft-KKDCPP-implementation, no longer needed - drop patch for 0008-Load-custom-anchors-when-using-KKDCP, no longer needed - drop patch for 0009-Check-names-in-the-server-s-cert-when-using-KKDCP, no longer needed - drop patch for 0010-Add-some-longer-form-docs-for-HTTPS, no longer needed - drop patch for 0011-Have-k5test.py-provide-runenv-to-python-tests, no longer needed - drop patch for 0012-Add-a-simple-KDC-proxy-test-server, no longer needed - drop patch for 0013-Add-tests-for-MS-KKDCP-client-support, no longer needed - drop patch for krb5-1.12ish-tls-plugins, fixed in krb5-1.13.1 - drop patch for krb5-1.12-nodelete-plugins, fixed in krb5-1.13.1 - drop patch for krb5-1.12-ksu-untyped-default-ccache-name, fixed in krb5-1.13.1 - drop patch for krb5-1.12-ksu-no-ccache, fixed in krb5-1.13.1 - drop patch for krb5-ksu_not_working_with_default_principal, fixed in krb5-1.13.1 - drop patch for CVE_2014_5353_fix_LDAP_misused_policy_name_crash, fixed in krb5-1.13.1 - drop patch for CVE_2014_5354_support_keyless_principals_in_ldap, fixed in krb5-1.13.1 - drop patch for kinit -C loops (MIT/krb5 bug #243), fixed in krb5-1.13.1 - drop patch for CVEs { 2014-9421, 2014-9422, 2014-9423, 2014-5352 }, fixed in krb5-1.13.1 - added patch krb5-1.14-Support-KDC_ERR_MORE_PREAUTH_DATA_REQUIRED - added patch krb5-1.12.1-CVE_2014_5355_fix_krb5_read_message_handling- Minor spec cleanup"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2154");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2154.html");
script_cve_id("CVE-2014-5355","CVE-2015-2694");
script_tag(name:"cvss_base", value:"5.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~10.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

