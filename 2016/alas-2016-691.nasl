# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-691.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120681");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-05-09 14:11:56 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-691");
script_tag(name: "insight", value: "An out-of-bounds read flaw was found in the kadmind service of MIT Kerberos. An authenticated attacker could send a maliciously crafted message to force kadmind to read beyond the end of allocated memory, and write the memory contents to the KDC database if the attacker has write permission, leading to information disclosure. (CVE-2015-8629 )A NULL pointer dereference flaw was found in the procedure used by the MIT Kerberos kadmind service to store policies: the kadm5_create_principal_3() and kadm5_modify_principal() function did not ensure that a policy was given when KADM5_POLICY was set. An authenticated attacker with permissions to modify the database could use this flaw to add or modify a principal with a policy set to NULL, causing the kadmind service to crash. (CVE-2015-8630 )A memory leak flaw was found in the krb5_unparse_name() function of the MIT Kerberos kadmind service. An authenticated attacker could repeatedly send specially crafted requests to the server, which could cause the server to consume large amounts of memory resources, ultimately leading to a denial of service due to memory exhaustion. (CVE-2015-8631 )"); 
script_tag(name : "solution", value : "Run yum update krb5 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-691.html");
script_cve_id("CVE-2015-8629","CVE-2015-8630","CVE-2015-8631");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.13.2~12.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
