# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-388.nasl 6759 2017-07-19 09:56:33Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120103");
script_version("$Revision: 6759 $");
script_tag(name:"creation_date", value:"2015-09-08 13:17:29 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-388");
script_tag(name: "insight", value: "A race condition flaw, leading to heap-based buffer overflows, was found in the mod_status httpd module. A remote attacker able to access a status page served by mod_status on a server using a threaded Multi-Processing Module (MPM) could send a specially crafted request that would cause the httpd child process to crash or, possibly, allow the attacker to execute arbitrary code with the privileges of the apache user. (CVE-2014-0226 )A denial of service flaw was found in the way httpd's mod_deflate module handled request body decompression (configured via the DEFLATE input filter). A remote attacker able to send a request whose body would be decompressed could use this flaw to consume an excessive amount of system memory and CPU on the target system. (CVE-2014-0118 )A denial of service flaw was found in the way httpd's mod_cgid module executed CGI scripts that did not read data from the standard input. A remote attacker could submit a specially crafted request that would cause the httpd child process to hang indefinitely. (CVE-2014-0231 )"); 
script_tag(name : "solution", value : "Run yum update httpd to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-388.html");
script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.27~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.27~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.27~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.27~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.27~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
