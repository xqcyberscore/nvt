# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891695");
  script_version("$Revision: 13949 $");
  script_cve_id("CVE-2017-15370", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-18189");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1695-1] sox security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 08:26:12 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-28 00:00:00 +0100 (Thu, 28 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00042.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"sox on Debian Linux");
  script_tag(name:"insight", value:"SoX is a command line utility that can convert various formats of computer
audio files in to other formats. It can also apply various effects to these
sound files during the conversion. As an added bonus, SoX can play and record
audio files on several unix-style platforms.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
14.4.1-5+deb8u2.

We recommend that you upgrade your sox packages.");
  script_tag(name:"summary", value:", 878810, 882144, 881121

Multiple vulnerabilities have been discovered in SoX (Sound eXchange),
a sound processing program:

CVE-2017-15370

The ImaAdpcmReadBlock function (src/wav.c) is affected by a heap buffer
overflow. This vulnerability might be leveraged by remote attackers
using a crafted WAV file to cause denial of service (application crash).

CVE-2017-15372

The lsx_ms_adpcm_block_expand_i function (adpcm.c) is affected by a
stack based buffer overflow. This vulnerability might be leveraged by
remote attackers using a crafted audio file to cause denial of service
(application crash).

CVE-2017-15642

The lsx_aiffstartread function (aiff.c) is affected by a use-after-free
vulnerability. This flaw might be leveraged by remote attackers using a
crafted AIFF file to cause denial of service (application crash).

CVE-2017-18189

The startread function (xa.c) is affected by a null pointer dereference
vulnerability. This flaw might be leveraged by remote attackers using a
crafted Maxis XA audio file to cause denial of service (application
crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libsox-dev", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-all", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-alsa", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-ao", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-base", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-mp3", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-oss", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox-fmt-pulse", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sox", ver:"14.4.1-5+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
