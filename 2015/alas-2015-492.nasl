# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-492.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120168");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:19:03 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-492");
script_tag(name: "insight", value: "A buffer overflow flaw was found in the way PostgreSQL handled certain numeric formatting. An authenticated database user could use a specially crafted timestamp formatting template to cause PostgreSQL to crash or, under certain conditions, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0241 )A buffer overflow flaw was found in the PostgreSQL's internal printf() implementation. An authenticated database user could use a specially crafted string in an SQL query to cause PostgreSQL to crash or, potentially, lead to privilege escalation. (CVE-2015-0242 )A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto module. An authenticated database user could use this flaw to cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0243 )A flaw was found in way PostgreSQL handled certain errors during that were generated during protocol synchronization. An authenticated database user could use this flaw to inject queries into an existing connection. (CVE-2015-0244 )The make check command for the test suites in PostgreSQL 9.3.3 and earlier does not properly invoke initdb to specify the authentication requirements for a database cluster to be used for the tests, which allows local users to gain privileges by leveraging access to this cluster. (CVE-2014-0067 )An information leak flaw was found in the way certain the PostgreSQL database server handled certain error messages. An authenticated database user could possibly obtain the results of a query they did not have privileges to execute by observing the constraint violation error messages produced when the query was executed. (CVE-2014-8161 )"); 
script_tag(name : "solution", value : "Run yum update postgresql92 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-492.html");
script_cve_id("CVE-2015-0244", "CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0242", "CVE-2014-0067");
script_tag(name:"cvss_base", value:"6.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"postgresql92-test", rpm:"postgresql92-test~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-libs", rpm:"postgresql92-libs~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-docs", rpm:"postgresql92-docs~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-plperl", rpm:"postgresql92-plperl~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-debuginfo", rpm:"postgresql92-debuginfo~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-plpython", rpm:"postgresql92-plpython~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-devel", rpm:"postgresql92-devel~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-server", rpm:"postgresql92-server~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-pltcl", rpm:"postgresql92-pltcl~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-contrib", rpm:"postgresql92-contrib~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92-server-compat", rpm:"postgresql92-server-compat~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql92", rpm:"postgresql92~9.2.10~1.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
