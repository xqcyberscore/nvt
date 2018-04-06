########################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3085.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3085-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
#############################################################################

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703085");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-9031", "CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035",
                  "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039");
    script_name("Debian Security Advisory DSA 3085-1 (wordpress - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2014-12-03 00:00:00 +0100 (Wed, 03 Dec 2014)");
    script_tag(name:"cvss_base", value:"6.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3085.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "wordpress on Debian Linux");
        script_tag(name: "insight",   value: "WordPress is a full featured web blogging tool:

* Instant publishing (no rebuilding)
* Comment pingback support with spam protection
* Non-crufty URLs
* Themable
* Plugin support");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
these problems have been fixed in version 3.6.1+dfsg-1~deb7u5.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 4.0.1+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.1+dfsg-1.

We recommend that you upgrade your wordpress packages.");
    script_tag(name: "summary",   value: "Multiple security issues have been
discovered in Wordpress, a web blogging tool, resulting in denial of service
or information disclosure. More information can be found in the upstream advisory
at https://wordpress.org/news/2014/11/wordpress-4-0-1/CVE-2014-9031
Jouko Pynnonen discovered an unauthenticated cross site scripting
vulnerability (XSS) in wptexturize(), exploitable via comments or
posts.

CVE-2014-9033
Cross site request forgery (CSRF) vulnerability in the password
changing process, which could be used by an attacker to trick an
user into changing her password.

CVE-2014-9034
Javier Nieto Arevalo and Andres Rojas Guerrero reported a potential
denial of service in the way the phpass library is used to handle
passwords, since no maximum password length was set.

CVE-2014-9035John Blackbourn reported an XSS in the Press This function (used
for quick publishing using a browser bookmarklet).

CVE-2014-9036
Robert Chapin reported an XSS in the HTML filtering of CSS in posts.

CVE-2014-9037
David Anderson reported a hash comparison vulnerability for
passwords stored using the old-style MD5 scheme. While unlikely,
this could be exploited to compromise an account, if the user had
not logged in after a Wordpress 2.5 update (uploaded to Debian on 2
Apr, 2008) and the password MD5 hash could be collided with due to
PHP dynamic comparison.

CVE-2014-9038
Ben Bidner reported a server side request forgery (SSRF) in the core
HTTP layer which unsufficiently blocked the loopback IP address
space.

CVE-2014-9039
Momen Bassel, Tanoy Bose, and Bojan Slavkovic reported a
vulnerability in the password reset process: an email address change
would not invalidate a previous password reset email.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
