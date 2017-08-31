# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-305.nasl 6692 2017-07-12 09:57:43Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120526");
script_version("$Revision: 6692 $");
script_tag(name:"creation_date", value:"2015-09-08 13:28:33 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-305");
script_tag(name: "insight", value: "Multiple stack-based buffer overflow flaws were found in the date/time implementation of PostgreSQL. An authenticated database user could provide a specially crafted date/time value that, when processed, could cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0063 )Multiple integer overflow flaws, leading to heap-based buffer overflows, were found in various type input functions in PostgreSQL. An authenticated database user could possibly use these flaws to crash PostgreSQL or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0064 )Multiple potential buffer overflow flaws were found in PostgreSQL. An authenticated database user could possibly use these flaws to crash PostgreSQL or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0065 )It was found that granting an SQL role to a database user in a PostgreSQL database without specifying the ADMIN option allowed the grantee to remove other users from their granted role. An authenticated database user could use this flaw to remove a user from an SQL role which they were granted access to. (CVE-2014-0060 )A flaw was found in the validator functions provided by PostgreSQL's procedural languages (PLs). An authenticated database user could possibly use this flaw to escalate their privileges. (CVE-2014-0061 )A race condition was found in the way the CREATE INDEX command performed multiple independent lookups of a table that had to be indexed. An authenticated database user could possibly use this flaw to escalate their privileges. (CVE-2014-0062 )It was found that the chkpass extension of PostgreSQL did not check the return value of the crypt() function. An authenticated database user could possibly use this flaw to crash PostgreSQL via a null pointer dereference. (CVE-2014-0066 )"); 
script_tag(name : "solution", value : "Run yum update postgresql8 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-305.html");
script_cve_id("CVE-2014-0066", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0060", "CVE-2014-0061");
script_tag(name:"cvss_base", value:"6.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"postgresql8-libs", rpm:"postgresql8-libs~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-test", rpm:"postgresql8-test~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-plpython", rpm:"postgresql8-plpython~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-debuginfo", rpm:"postgresql8-debuginfo~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-pltcl", rpm:"postgresql8-pltcl~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-devel", rpm:"postgresql8-devel~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-plperl", rpm:"postgresql8-plperl~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-contrib", rpm:"postgresql8-contrib~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8", rpm:"postgresql8~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-server", rpm:"postgresql8-server~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-docs", rpm:"postgresql8-docs~8.4.20~1.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
