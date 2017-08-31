# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-46.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120253");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:21:35 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-46");
script_tag(name: "insight", value: "It was discovered that the fix for CVE-2011-3368  did not completely address the problem. An attacker could bypass the fix and make a reverse proxy connect to an arbitrary server not directly accessible to the attacker by sending an HTTP version 0.9 request, or by using a specially-crafted URI. (CVE-2011-3639 , CVE-2011-4317 )The httpd server included the full HTTP header line in the default error page generated when receiving an excessively long or malformed header. Malicious JavaScript running in the server's domain context could use this flaw to gain access to httpOnly cookies. (CVE-2012-0053 )An integer overflow flaw, leading to a heap-based buffer overflow, was found in the way httpd performed substitutions in regular expressions. An attacker able to set certain httpd settings, such as a user permitted to override the httpd configuration for a specific directory using a .htaccess file, could use this flaw to crash the httpd child process or, possibly, execute arbitrary code with the privileges of the apache user. (CVE-2011-3607 )A flaw was found in the way httpd handled child process status information. A malicious program running with httpd child process privileges (such as a PHP or CGI script) could use this flaw to cause the parent httpd process to crash during httpd service shutdown. (CVE-2012-0031 )"); 
script_tag(name : "solution", value : "Run yum update httpd to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-46.html");
script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2012-0031", "CVE-2012-0053");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.22~1.23.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.22~1.23.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.22~1.23.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.22~1.23.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.22~1.23.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
