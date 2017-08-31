# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-503.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120366");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:24:42 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-503");
script_tag(name: "insight", value: "An information leak flaw was found in the way the PostgreSQL database server handled certain error messages. An authenticated database user could possibly obtain the results of a query they did not have privileges to execute by observing the constraint violation error messages produced when the query was executed. (CVE-2014-8161 )A buffer overflow flaw was found in the way PostgreSQL handled certain numeric formatting. An authenticated database user could use a specially crafted timestamp formatting template to cause PostgreSQL to crash or, under certain conditions, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0241 )A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto module. An authenticated database user could use this flaw to cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0243 )A flaw was found in the way PostgreSQL handled certain errors that were generated during protocol synchronization. An authenticated database user could use this flaw to inject queries into an existing connection. (CVE-2015-0244 )"); 
script_tag(name : "solution", value : "Run yum update postgresql8 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-503.html");
script_cve_id("CVE-2015-0244", "CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243");
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
if ((res = isrpmvuln(pkg:"postgresql8-plpython", rpm:"postgresql8-plpython~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-plperl", rpm:"postgresql8-plperl~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-docs", rpm:"postgresql8-docs~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-libs", rpm:"postgresql8-libs~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8", rpm:"postgresql8~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-debuginfo", rpm:"postgresql8-debuginfo~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-server", rpm:"postgresql8-server~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-contrib", rpm:"postgresql8-contrib~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-pltcl", rpm:"postgresql8-pltcl~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-test", rpm:"postgresql8-test~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"postgresql8-devel", rpm:"postgresql8-devel~8.4.20~2.48.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
