###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4182.nasl 9671 2018-04-29 07:33:34Z cfischer $
#
# Auto-generated from advisory DSA 4182-1 using nvtgen 1.0
# Script version: 1.0
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.704182");
  script_version("$Revision: 9671 $");
  script_cve_id("CVE-2018-6056", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062",
                "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067",
                "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072",
                "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077",
                "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082",
                "CVE-2018-6083", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088",
                "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093",
                "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098",
                "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103",
                "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108",
                "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113",
                "CVE-2018-6114", "CVE-2018-6116", "CVE-2018-6117");
  script_name("Debian Security Advisory DSA 4182-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-29 09:33:34 +0200 (Sun, 29 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-28 00:00:00 +0200 (Sat, 28 Apr 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4182.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9\.[0-9]+");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), security support for chromium
has been discontinued.

For the stable distribution (stretch), these problems have been fixed in
version 66.0.3359.117-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary",  value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-6056 
lokihardt discovered an error in the v8 javascript library.

CVE-2018-6057 
Gal Beniamini discovered errors related to shared memory permissions.

CVE-2018-6060 
Omair discovered a use-after-free issue in blink/webkit.

CVE-2018-6061 
Guang Gong discovered a race condition in the v8 javascript library.

CVE-2018-6062 
A heap overflow issue was discovered in the v8 javascript library.

CVE-2018-6063 
Gal Beniamini discovered errors related to shared memory permissions.

CVE-2018-6064 
lokihardt discovered a type confusion error in the v8 javascript
library.

CVE-2018-6065 
Mark Brand discovered an integer overflow issue in the v8 javascript
library.

CVE-2018-6066 
Masato Kinugawa discovered a way to bypass the Same Origin Policy.

CVE-2018-6067 
Ned Williamson discovered a buffer overflow issue in the skia library.

CVE-2018-6068 
Luan Herrera discovered object lifecycle issues.

CVE-2018-6069 
Wanglu and Yangkang discovered a stack overflow issue in the skia
library.

CVE-2018-6070 
Rob Wu discovered a way to bypass the Content Security Policy.

CVE-2018-6071 
A heap overflow issue was discovered in the skia library.

CVE-2018-6072 
Atte Kettunen discovered an integer overflow issue in the pdfium
library.

CVE-2018-6073 
Omair discover a heap overflow issue in the WebGL implementation.

CVE-2018-6074 
Abdulrahman Alqabandi discovered a way to cause a downloaded web page
to not contain a Mark of the Web.

CVE-2018-6075 
Inti De Ceukelaire discovered a way to bypass the Same Origin Policy.

CVE-2018-6076 
Mateusz Krzeszowiec discovered that URL fragment identifiers could be
handled incorrectly.

CVE-2018-6077 
Khalil Zhani discovered a timing issue.

CVE-2018-6078 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6079 
Ivars discovered an information disclosure issue.

CVE-2018-6080 
Gal Beniamini discovered an information disclosure issue.

CVE-2018-6081 
Rob Wu discovered a cross-site scripting issue.

CVE-2018-6082 
WenXu Wu discovered a way to bypass blocked ports.

CVE-2018-6083 
Jun Kokatsu discovered that AppManifests could be handled incorrectly.

CVE-2018-6085 
Ned Williamson discovered a use-after-free issue.

CVE-2018-6086 
Ned Williamson discovered a use-after-free issue.

CVE-2018-6087 
A use-after-free issue was discovered in the WebAssembly implementation.

CVE-2018-6088 
A use-after-free issue was discovered in the pdfium library.

CVE-2018-6089 
Rob Wu discovered a way to bypass the Same Origin Policy.

CVE-2018-6090 
ZhanJia Song discovered a heap overflow issue in the skia library.

CVE-2018-6091 
Jun Kokatsu discovered that plugins could be handled incorrectly.

CVE-2018-6092 
Natalie Silvanovich discovered an integer overflow issue in the
WebAssembly implementation.

CVE-2018-6093 
Jun Kokatsu discovered a way to bypass the Same Origin Policy.

CVE-2018-6094 
Chris Rohlf discovered a regression in garbage collection hardening.

CVE-2018-6095 
Abdulrahman Alqabandi discovered files could be uploaded without user
interaction.

CVE-2018-6096 
WenXu Wu discovered a user interface spoofing issue.

CVE-2018-6097 
xisigr discovered a user interface spoofing issue.

CVE-2018-6098 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6099 
Jun Kokatsu discovered a way to bypass the Cross Origin Resource
Sharing mechanism.

CVE-2018-6100 
Lnyas Zhang discovered a URL spoofing issue.

CVE-2018-6101 
Rob Wu discovered an issue in the developer tools remote debugging
protocol.

CVE-2018-6102 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6103 
Khalil Zhani discovered a user interface spoofing issue.

CVE-2018-6104 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6105 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6106 
lokihardt discovered that v8 promises could be handled incorrectly.

CVE-2018-6107 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6108 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6109 
Dominik Weber discovered a way to misuse the FileAPI feature.

CVE-2018-6110 
Wenxiang Qian discovered that local plain text files could be handled
incorrectly.

CVE-2018-6111 
Khalil Zhani discovered a use-after-free issue in the developer tools.

CVE-2018-6112 
Khalil Zhani discovered incorrect handling of URLs in the developer
tools.

CVE-2018-6113 
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6114 
Lnyas Zhang discovered a way to bypass the Content Security Policy.

CVE-2018-6116 
Chengdu Security Response Center discovered an error when memory
is low.

CVE-2018-6117 
Spencer Dailey discovered an error in form autofill settings.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"chromedriver", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-driver", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-l10n", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-shell", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-widevine", ver:"66.0.3359.117-1~deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
