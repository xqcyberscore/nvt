# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-266.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120463");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:26:57 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-266");
script_tag(name: "insight", value: "A flaw was found in the way NSS handled invalid handshake packets. A remote attacker could use this flaw to cause a TLS/SSL client using NSS to crash or, possibly, execute arbitrary code with the privileges of the user running the application. (CVE-2013-5605 )It was found that the fix for CVE-2013-1620  introduced a regression causing NSS to read uninitialized data when a decryption failure occurred. A remote attacker could use this flaw to cause a TLS/SSL server using NSS to crash. (CVE-2013-1739 )An integer overflow flaw was discovered in both NSS and NSPR's implementation of certification parsing on 64-bit systems. A remote attacker could use these flaws to cause an application using NSS or NSPR to crash. (CVE-2013-1741 , CVE-2013-5607 )It was discovered that NSS did not reject certificates with incompatible key usage constraints when validating them while the verifyLog feature was enabled. An application using the NSS certificate validation API could accept an invalid certificate. (CVE-2013-5606 )"); 
script_tag(name : "solution", value : "Run yum update nspr to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-266.html");
script_cve_id("CVE-2013-1741", "CVE-2013-1739", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607", "CVE-2013-1620");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.10.2~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.2~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.2~1.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
