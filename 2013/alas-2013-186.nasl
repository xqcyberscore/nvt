# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-186.nasl 4515 2016-11-15 10:21:35Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120274");
script_version("$Revision: 4515 $");
script_tag(name:"creation_date", value:"2015-09-08 13:22:16 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 11:21:35 +0100 (Tue, 15 Nov 2016) $");
script_name("Amazon Linux Local Check: ALAS-2013-186");
script_tag(name: "insight", value: "This update fixes several vulnerabilities in the MySQL database server. Information about these flaws can be found in the References section."); 
script_tag(name : "solution", value : "Run yum update mysql51 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-186.html");
script_cve_id("CVE-2013-2375", "CVE-2013-2389", "CVE-2013-1544", "CVE-2013-1532", "CVE-2013-1521", "CVE-2013-2392", "CVE-2013-1506", "CVE-2013-2378", "CVE-2012-5614", "CVE-2013-2391", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1531", "CVE-2013-1555");
script_tag(name:"cvss_base", value:"6.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("HostDetails/OS/cpe:/o:amazon:linux", "login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_summary("Amazon Linux Local Security Checks ALAS-2013-186");
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
if ((res = isrpmvuln(pkg:"mysql51-bench", rpm:"mysql51-bench~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-embedded-devel", rpm:"mysql51-embedded-devel~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-devel", rpm:"mysql51-devel~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-debuginfo", rpm:"mysql51-debuginfo~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-libs", rpm:"mysql51-libs~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-test", rpm:"mysql51-test~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51", rpm:"mysql51~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-embedded", rpm:"mysql51-embedded~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-common", rpm:"mysql51-common~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql51-server", rpm:"mysql51-server~5.1.69~1.63.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
