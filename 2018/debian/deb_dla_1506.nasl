###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1506.nasl 11442 2018-09-18 04:35:38Z ckuersteiner $
#
# Auto-generated from advisory DLA 1506-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891506");
  script_version("$Revision: 11442 $");
  script_cve_id("CVE-2017-5715", "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3640",
                "CVE-2018-3646");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1506-1] intel-microcode security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 06:35:38 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-17 00:00:00 +0200 (Mon, 17 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"intel-microcode on Debian Linux");
  script_tag(name:"insight", value:"This package contains updated system processor microcode for
Intel i686 and Intel X86-64 processors. Intel releases microcode
updates to correct processor behavior as documented in the
respective processor specification updates.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.20180807a.1~deb8u1.

We recommend that you upgrade your intel-microcode packages.");
  script_tag(name:"summary",  value:"Security researchers identified speculative execution side-channel
methods which have the potential to improperly gather sensitive data
from multiple types of computing devices with different vendors
processors and operating systems.

This update requires an update to the intel-microcode package, which is
non-free. It is related to DLA-1446-1 and adds more mitigations for
additional types of Intel processors.

For more information please also read the official Intel security
advisories at:

https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00088.html
https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00115.html
https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00161.html");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20180807a.1~deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
