# OpenVAS Vulnerability Test
# $Id: deb_2824.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2824-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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

include("revisions-lib.inc");

tag_affected  = "curl on Debian Linux";
tag_insight   = "curl is a command line tool for transferring data with URL syntax, supporting
DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy7.

For the unstable distribution (sid), this problem has been fixed in
version 7.34.0-1.

We recommend that you upgrade your curl packages.";
tag_summary   = "Marc Deslauriers discovered that curl, a file retrieval tool, would
mistakenly skip verifying the CN and SAN name fields when digital
signature verification was disabled in the libcurl GnuTLS backend.

The default configuration for the curl package is not affected by this
issue since the digital signature verification is enabled by default.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702824");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-6422");
    script_name("Debian Security Advisory DSA 2824-1 (curl - unchecked tls/ssl certificate host name)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-12-19 00:00:00 +0100 (Thu, 19 Dec 2013)");
    script_tag(name: "cvss_base", value:"4.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2824.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
