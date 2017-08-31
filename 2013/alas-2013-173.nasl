# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-173.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120557");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:29:32 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-173");
script_tag(name: "insight", value: "It was discovered that Ruby's REXML library did not properly restrict XML entity expansion. An attacker could use this flaw to cause a denial of service by tricking a Ruby application using REXML to read text nodes from specially-crafted XML content, which will result in REXML consuming large amounts of system memory. (CVE-2013-1821 )It was found that the RHSA-2011-0910  update did not correctly fix the CVE-2011-1005  issue, a flaw in the method for translating an exception message into a string in the Exception class. A remote attacker could use this flaw to bypass safe level 4 restrictions, allowing untrusted (tainted) code to modify arbitrary, trusted (untainted) strings, which safe level 4 restrictions would otherwise prevent. (CVE-2012-4481 )The safe-level feature in Ruby 1.8.6 through 1.8.6-420, 1.8.7 through 1.8.7-330, and 1.8.8dev allows context-dependent attackers to modify strings via the Exception#to_s method, as demonstrated by changing an intended pathname. (CVE-2011-1005 )"); 
script_tag(name : "solution", value : "Run yum update ruby to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-173.html");
script_cve_id("CVE-2012-4481", "CVE-2011-1005", "CVE-2013-1821");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
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
if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby-static", rpm:"ruby-static~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.7.371~2.25.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
