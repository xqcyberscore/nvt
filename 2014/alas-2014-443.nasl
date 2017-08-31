# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-443.nasl 6637 2017-07-10 09:58:13Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
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
script_oid("1.3.6.1.4.1.25623.1.0.120422");
script_version("$Revision: 6637 $");
script_tag(name:"creation_date", value:"2015-09-08 13:25:59 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-443");
script_tag(name: "insight", value: "It was found that if a KDC served multiple realms, certain requests could cause the setup_server_realm() function to dereference a NULL pointer. A remote, unauthenticated attacker could use this flaw to crash the KDC using a specially crafted request. (CVE-2013-1418 , CVE-2013-6800 )A NULL pointer dereference flaw was found in the MIT Kerberos SPNEGO acceptor for continuation tokens. A remote, unauthenticated attacker could use this flaw to crash a GSSAPI-enabled server application. (CVE-2014-4344 )A buffer overflow was found in the KADM5 administration server (kadmind) when it was used with an LDAP back end for the KDC database. A remote, authenticated attacker could potentially use this flaw to execute arbitrary code on the system running kadmind. (CVE-2014-4345 )Two buffer over-read flaws were found in the way MIT Kerberos handled certain requests. A remote, unauthenticated attacker who is able to inject packets into a client or server application's GSSAPI session could use either of these flaws to crash the application. (CVE-2014-4341 , CVE-2014-4342 )A double-free flaw was found in the MIT Kerberos SPNEGO initiators. An attacker able to spoof packets to appear as though they are from an GSSAPI acceptor could use this flaw to crash a client application that uses MIT Kerberos. (CVE-2014-4343 )"); 
script_tag(name : "solution", value : "Run yum update krb5 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-443.html");
script_cve_id("CVE-2014-4342", "CVE-2013-6800", "CVE-2014-4343", "CVE-2013-1418", "CVE-2014-4341", "CVE-2014-4345", "CVE-2014-4344");
script_tag(name:"cvss_base", value:"8.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.10.3~33.28.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
