# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1462.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123061");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1462");
script_tag(name: "insight", value: "ELSA-2015-1462 -  ipa security and bug fix update - [3.0.0-47.el6]- Resolves: #1220788 - Some IPA schema files are not RFC 4512 compliant[3.0.0-46.el6]- Use tls version range in NSSHTTPS initialization- Resolves: #1154687 - POODLE: force using safe ciphers (non-SSLv3) in IPA client and server- Resolves: #1012224 - host certificate not issued to client during ipa-client-install[3.0.0-45.el6]- Resolves: #1205660 - ipa-client rpm should require keyutils[3.0.0-44.el6]- Release 3.0.0-44- Resolves: #1201454 - ipa breaks sshd config[3.0.0-43.el6]- Release 3.0.0-43- Resolves: #1191040 - ipa-client-automount: failing with error LDAP server returned UNWILLING_TO_PERFORM. This likely means that minssf is enabled.- Resolves: #1185207 - ipa-client dont end new line character in /etc/nsswitch.conf- Resolves: #1166241 - CVE-2010-5312 CVE-2012-6662 ipa: various flaws- Resolves: #1161722 - IDM client registration failure in a high load environment- Resolves: #1154687 - POODLE: force using safe ciphers (non-SSLv3) in IPA client and server- Resolves: #1146870 - ipa-client-install fails with 'KerbTransport instance has no attribute '__conn'' traceback- Resolves: #1132261 - ipa-client-install failing produces a traceback instead of useful error message- Resolves: #1131571 - Do not allow IdM server/replica/client installation in a FIPS-140 mode- Resolves: #1198160 - /usr/sbin/ipa-server-install --uninstall does not clean /var/lib/ipa/pki-ca- Resolves: #1198339 - ipa-client-install adds extra sss to sudoers in nsswitch.conf- Require: 389-ds-base >= 1.2.11.15-51- Require: mod_nss >= 1.0.10- Require: pki-ca >= 9.0.3-40- Require: python-nss >= 0.16"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1462");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1462.html");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

