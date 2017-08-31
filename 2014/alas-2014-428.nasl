# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-428.nasl 6735 2017-07-17 09:56:49Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120190");
script_version("$Revision: 6735 $");
script_tag(name:"creation_date", value:"2015-09-08 13:19:33 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-428");
script_tag(name: "insight", value: "Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized takeover of MySQL Server possibly including arbitrary code execution within the MySQL Server. (CVE-2014-6491 )Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: C API SSL CERTIFICATE HANDLING). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Difficult to exploit vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized read access to all MySQL Server accessible data. (CVE-2014-6559 )Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized takeover of MySQL Server possibly including arbitrary code execution within the MySQL Server. (CVE-2014-6500 )Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: CLIENT:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Difficult to exploit vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2014-6494 )"); 
script_tag(name : "solution", value : "Run yum update mysql55 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-428.html");
script_cve_id("CVE-2014-6491", "CVE-2014-6559", "CVE-2014-6500", "CVE-2014-6494");
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
if ((res = isrpmvuln(pkg:"mysql55-common", rpm:"mysql55-common~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-embedded-devel", rpm:"mysql55-embedded-devel~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-devel", rpm:"mysql55-devel~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-debuginfo", rpm:"mysql55-debuginfo~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-embedded", rpm:"mysql55-embedded~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-bench", rpm:"mysql55-bench~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-test", rpm:"mysql55-test~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-server", rpm:"mysql55-server~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55-libs", rpm:"mysql55-libs~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql55", rpm:"mysql55~5.5.40~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
