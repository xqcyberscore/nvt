#
#VID da3d381b-0ee6-11e0-becc-0022156e8794
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID da3d381b-0ee6-11e0-becc-0022156e8794
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "The following package is affected: pecl-phar

CVE-2010-2094
Multiple format string vulnerabilities in the phar extension in PHP
5.3 before 5.3.2 allow context-dependent attackers to obtain sensitive
information (memory contents) and possibly execute arbitrary code via
a crafted phar:// URI that is not properly handled by the (1)
phar_stream_flush, (2) phar_wrapper_unlink, (3) phar_parse_url, or (4)
phar_wrapper_open_url functions in ext/phar/stream.c; and the (5)
phar_wrapper_open_dir function in ext/phar/dirstream.c, which triggers
errors in the php_stream_wrapper_log_error function.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html
http://php-security.org/2010/05/14/mops-2010-025-php-phar_wrapper_open_dir-format-string-vulnerability/index.htm
http://php-security.org/2010/05/14/mops-2010-026-php-phar_wrapper_unlink-format-string-vulnerability/index.htm
http://php-security.org/2010/05/14/mops-2010-027-php-phar_parse_url-format-string-vulnerabilities/index.htm
http://php-security.org/2010/05/14/mops-2010-028-php-phar_wrapper_open_url-format-string-vulnerabilities/index.html
http://www.vuxml.org/freebsd/da3d381b-0ee6-11e0-becc-0022156e8794.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68831");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2094");
 script_name("FreeBSD Ports: pecl-phar");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"pecl-phar");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package pecl-phar version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
