###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_975.nasl 8633 2018-02-02 03:52:21Z ckuersteiner $
#
# Auto-generated from advisory DLA 975-1 using nvtgen 1.0
# Script version:1.0
# #
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890975");
  script_version("$Revision: 8633 $");
  script_cve_id("CVE-2017-8295", "CVE-2017-9061", "CVE-2017-9062", "CVE-2017-9063", "CVE-2017-9064", "CVE-2017-9065");
  script_name("Debian Lts Announce DLA 975-1 ([SECURITY] [DLA 975-1] wordpress security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-02-02 04:52:21 +0100 (Fri, 02 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00004.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"wordpress on Debian Linux");
  script_tag(name:"insight", value:"WordPress is a full featured web blogging tool:

* Instant publishing (no rebuilding)
* Comment pingback support with spam protection
* Non-crufty URLs
* Themable
* Plugin support");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u15.

We recommend that you upgrade your wordpress packages.");
  script_tag(name:"summary",  value:"Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-8295

    Potential unauthorized password reset vulnerability. More
    information are available at:

https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html

CVE-2017-9061

    A cross-site scripting (XSS) vulnerability exists when someone
    attempts to upload very large files.

CVE-2017-9062

    Improper handling of post meta data values in the XML-RPC API.

CVE-2017-9063

   Cross-site scripting (XSS) vulnerability in the customizer.

CVE-2017-9064

    A Cross Site Request Forgery (CSRF) vulnerability exists in the
    filesystem credentials dialog.

CVE-2017-9065

    Lack of capability checks for post meta data in the XML-RPC API.
");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u15", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u15", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
