###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2373_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for thunderbird USN-2373-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.842008");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-10-16 06:00:32 +0200 (Thu, 16 Oct 2014)");
  script_cve_id("CVE-2014-1574", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578",
                "CVE-2014-1581", "CVE-2014-1585", "CVE-2014-1586");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for thunderbird USN-2373-1");

  script_tag(name: "summary", value: "Check the version of thunderbird");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of
detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Bobby Holley, Christian Holler,
David Bolter, Byron Campen and Jon Coppeard discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a specially
crafted message with scripting enabled, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2014-1574)

Atte Kettunen discovered a buffer overflow during CSS manipulation. If a
user were tricked in to opening a specially crafted message, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2014-1576)

Holger Fuhrmannek discovered an out-of-bounds read with Web Audio. If a
user were tricked in to opening a specially crafted message with scripting
enabled, an attacker could potentially exploit this to steal sensitive
information. (CVE-2014-1577)

Abhishek Arya discovered an out-of-bounds write when buffering WebM video
in some circumstances. If a user were tricked in to opening a specially
crafted message with scripting enabled, an attacker could potentially
exploit this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1578)

A use-after-free was discovered during text layout in some circumstances.
If a user were tricked in to opening a specially crafted message with
scripting enabled, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1581)

Eric Shepherd and Jan-Ivar Bruaroey discovered issues with video sharing
via WebRTC in iframes, where video continues to be shared after being
stopped and navigating to a new site doesn't turn off the camera. An
attacker could potentially exploit this to access the camera without the
user being aware. (CVE-2014-1585, CVE-2014-1586)");
  script_tag(name: "affected", value: "thunderbird on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2373-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2373-1/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:31.2.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:31.2.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
