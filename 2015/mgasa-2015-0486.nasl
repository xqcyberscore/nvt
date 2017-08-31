# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0486.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131161");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-12-28 10:39:24 +0200 (Mon, 28 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0486");
script_tag(name: "insight", value: "Updated mediawiki packages fix security vulnerabilities: In MediaWiki before 1.23.12, an XSS vector exists when MediaWiki is configured with a non-standard configuration, from wikitext when $wgArticlePath='$1' (CVE-2015-8622). In MediaWiki before 1.23.12, tokens were being compared as strings, which could allow a timing attack (CVE-2015-8623, CVE-2015-8624). In MediaWiki before 1.23.12, parameters passed to the curl library were not sanitized, which could cause curl to upload files from the webserver to an attacker when POST variable starts with '@' (CVE-2015-8625). In MediaWiki before 1.23.12, the password reset token could be shorter than the minimum required password length (CVE-2015-8626). In MediaWiki before 1.23.12, blocking IP addresses with zero-padded octets resulted in a failure to block the IP address (CVE-2015-8627). In MediaWiki before 1.23.12, a combination of Special:MyPage redirects and pagecounts allows an external site to know the wikipedia login of an user (CVE-2015-8628)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0486.html");
script_cve_id("CVE-2015-8622","CVE-2015-8623","CVE-2015-8624","CVE-2015-8625","CVE-2015-8626","CVE-2015-8627","CVE-2015-8628");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0486");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.12~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
