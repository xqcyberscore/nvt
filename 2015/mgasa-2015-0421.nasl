# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0421.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131120");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-08 13:02:15 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0421");
script_tag(name: "insight", value: "Updated mediawiki packages fix security vulnerabilities: In MediaWiki before 1.23.11, the API failed to correctly stop adding new chunks to the upload when the reported size was exceeded, allowing a malicious user to upload add an infinite number of chunks for a single file upload (CVE-2015-8001). In MediaWiki before 1.23.11, a malicious user could upload chunks of 1 byte for very large files, potentially creating a very large number of files on the server's filesystem (CVE-2015-8002). In MediaWiki before 1.23.11, it is not possible to throttle file uploads, or in other words, rate limit them (CVE-2015-8003). In MediaWiki before 1.23.11, a missing authorization check when removing suppression from a revision allowed users with the 'viewsuppressed' user right but not the appropriate 'suppressrevision' user right to unsuppress revisions (CVE-2015-8004). In MediaWiki before 1.23.11, thumbnails of PNG files generated with ImageMagick contained the local file path in the image (CVE-2015-8005)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0421.html");
script_cve_id("CVE-2015-8001","CVE-2015-8002","CVE-2015-8003","CVE-2015-8004","CVE-2015-8005");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0421");
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
if ((res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.11~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
