# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-518.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120539");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:29:00 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-518");
script_tag(name: "insight", value: "A use-after-free flaw was found in the way the MIT Kerberos libgssapi_krb5 library processed valid context deletion tokens. An attacker able to make an application using the GSS-API library (libgssapi) could call the gss_process_context_token() function and use this flaw to crash that application. (CVE-2014-5352 )If kadmind were used with an LDAP back end for the KDC database, a remote, authenticated attacker who has the permissions to set the password policy could crash kadmind by attempting to use a named ticket policy object as a password policy for a principal. (CVE-2014-5353 )It was found that the krb5_read_message() function of MIT Kerberos did not correctly sanitize input, and could create invalid krb5_data objects. A remote, unauthenticated attacker could use this flaw to crash a Kerberos child process via a specially crafted request. (CVE-2014-5355 )A double-free flaw was found in the way MIT Kerberos handled invalid External Data Representation (XDR) data. An authenticated user could use this flaw to crash the MIT Kerberos administration server (kadmind), or other applications using Kerberos libraries, via specially crafted XDR packets. (CVE-2014-9421 )It was found that the MIT Kerberos administration server (kadmind) incorrectly accepted certain authentication requests for two-component server principal names. A remote attacker able to acquire a key with a particularly named principal (such as kad/x) could use this flaw to impersonate any user to kadmind, and perform administrative actions as that user. (CVE-2014-9422 )"); 
script_tag(name : "solution", value : "Run yum update krb5 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-518.html");
script_cve_id("CVE-2014-5353", "CVE-2014-5352", "CVE-2014-9421", "CVE-2014-5355", "CVE-2014-9422");
script_tag(name:"cvss_base", value:"9.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.10.3~37.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
