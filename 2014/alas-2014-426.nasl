# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-426.nasl 6637 2017-07-10 09:58:13Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120188");
script_version("$Revision: 6637 $");
script_tag(name:"creation_date", value:"2015-09-08 13:19:31 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-426");
script_tag(name: "insight", value: "Bodo Moller, Thai Duong and Krzysztof Kotowicz of Google discovered a flaw in the design of SSL version 3.0 that would allow an attacker to calculate the plaintext of secure connections, allowing, for example, secure HTTP cookies to be stolen.http://googleonlinesecurity.blogspot.com/2014/10/this-poodle-bites-exploiting-ssl-30.htmlhttps://www.openssl.org/~bodo/ssl-poodle.pdfSpecial notes:We have backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI repositories with updated openssl packages that fix CVE-2014-3566 .For 2014.09 Amazon Linux AMIs, openssl-1.0.1i-1.79.amzn1 addresses this CVE.  Running yum clean all followed by yum update openssl will install the fixed package.For Amazon Linux AMIs locked to the 2014.03 repositories, openssl-1.0.1i-1.79.amzn1 also addresses this CVE.  Running yum clean all followed by yum update openssl will install the fixed package.For Amazon Linux AMIs locked to the 2013.09 or 2013.03 repositories, openssl-1.0.1e-4.60.amzn1 addresses this CVE.  Running yum clean all followed by yum update openssl will install the fixed package.If you are using a pre-2013.03 Amazon Linux AMI, we encourage you to move to a newer version of the Amazon Linux AMI as soon as possible."); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.   Note that you may need to run yum clean all first.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-426.html");
script_cve_id("CVE-2014-3566");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
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
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~1.79.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1i~1.79.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1i~1.79.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1i~1.79.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1i~1.79.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
