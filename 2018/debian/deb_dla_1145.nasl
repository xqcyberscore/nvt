###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1145.nasl 10219 2018-06-15 12:00:55Z cfischer $
#
# Auto-generated from advisory DLA 1145-1 using nvtgen 1.0
# Script version:1.2
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
  script_oid("1.3.6.1.4.1.25623.1.0.891145");
  script_version("$Revision: 10219 $");
  script_cve_id("CVE-2017-5595");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1145-1] zoneminder security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 14:00:55 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7\.[0-9]+");
  script_tag(name:"affected", value:"zoneminder on Debian Linux");
  script_tag(name:"insight", value:"ZoneMinder is intended for use in single or multi-camera video security
applications, including commercial or home CCTV, theft prevention and child
or family member or home monitoring and other care scenarios. It
supports capture, analysis, recording, and monitoring of video data coming
from one or more video or network cameras attached to a Linux system.
ZoneMinder also support web and semi-automatic control of Pan/Tilt/Zoom
cameras using a variety of protocols. It is suitable for use as a home
video security system and for commercial or professional video security
and surveillance. It can also be integrated into a home automation system
via X.10 or other protocols.");
  script_tag(name:"solution", value:"The application has been found to suffer from many other problems
such as SQL injection vulnerabilities, cross-site scripting issues,
cross-site request forgery, session fixation vulnerability. Due to the
amount of issues and to the relative invasiveness of the relevant patches,
those issues will not be fixed in Wheezy. We thus advise you to restrict
access to zoneminder to trusted users only. If you want to review the
list of ignored issues, you can check the security tracker:
https://security-tracker.debian.org/tracker/source-package/zoneminder.

We recommend that you upgrade your zoneminder packages.");
  script_tag(name:"summary",  value:"Multiple vulnerabilities have been found in zoneminder. This update
fixes only a serious file disclosure vulnerability (CVE-2017-5595).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"zoneminder", ver:"1.25.0-4+deb7u2", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
