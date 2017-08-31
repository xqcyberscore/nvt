# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-686.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
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
script_oid("1.3.6.1.4.1.25623.1.0.120676");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-05-09 14:11:52 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-686");
script_tag(name: "insight", value: "Multiple flaws were found in Samba&#039;s DCE/RPC protocol implementation. A remote, authenticated attacker could use these flaws to cause a denial of service against the Samba server (high CPU load or a crash) or, possibly, execute arbitrary code with the permissions of the user running Samba (root). This flaw could also be used to downgrade a secure DCE/RPC connection by a man-in-the-middle attacker taking control of an Active Directory (AD) object and compromising the security of a Samba Active Directory Domain Controller (DC). (CVE-2015-5370 )A protocol flaw, publicly referred to as Badlock, was found in the Security Account Manager Remote Protocol (MS-SAMR) and the Local Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any authenticated DCE/RPC connection that a client initiates against a server could be used by a man-in-the-middle attacker to impersonate the authenticated user against the SAMR or LSA service on the server. As a result, the attacker would be able to get read/write access to the Security Account Manager database, and use this to reveal all passwords or any other potentially sensitive information in that database. (CVE-2016-2118 )Several flaws were found in Samba&#039;s implementation of NTLMSSP authentication. An unauthenticated, man-in-the-middle attacker could use this flaw to clear the encryption and integrity flags of a connection, causing data to be transmitted in plain text. The attacker could also force the client or server into sending data in plain text even if encryption was explicitly requested for that connection. (CVE-2016-2110 )It was discovered that Samba configured as a Domain Controller would establish a secure communication channel with a machine using a spoofed computer name. A remote attacker able to observe network traffic could use this flaw to obtain session-related information about the spoofed machine. (CVE-2016-2111 )It was found that Samba&#039;s LDAP implementation did not enforce integrity protection for LDAP connections. A man-in-the-middle attacker could use this flaw to downgrade LDAP connections to use no integrity protection, allowing them to hijack such connections. (CVE-2016-2112 )It was found that Samba did not validate SSL/TLS certificates in certain connections. A man-in-the-middle attacker could use this flaw to spoof a Samba server using a specially crafted SSL/TLS certificate. (CVE-2016-2113 )It was discovered that Samba did not enforce Server Message Block (SMB) signing for clients using the SMB1 protocol. A man-in-the-middle attacker could use this flaw to modify traffic between a client and a server. (CVE-2016-2114 )It was found that Samba did not enable integrity protection for IPC traffic by default. A man-in-the-middle attacker could use this flaw to view and modify the data sent between a Samba server and a client. (CVE-2016-2115 )"); 
script_tag(name : "solution", value : "Run yum update samba to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-686.html");
script_cve_id("CVE-2016-2118","CVE-2016-2114","CVE-2016-2115","CVE-2016-2112","CVE-2016-2113","CVE-2016-2110","CVE-2016-2111","CVE-2015-5370");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
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
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"ctdb-tests", rpm:"ctdb-tests~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ctdb-devel", rpm:"ctdb-devel~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-common-libs", rpm:"samba-common-libs~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-test-devel", rpm:"samba-test-devel~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-test-libs", rpm:"samba-test-libs~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-pidl", rpm:"samba-pidl~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.2.10~6.33.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
