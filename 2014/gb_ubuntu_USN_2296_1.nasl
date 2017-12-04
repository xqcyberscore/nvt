###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2296_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for thunderbird USN-2296-1
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

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841909");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-07-28 16:38:12 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-1547", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1555",
                "CVE-2014-1556", "CVE-2014-1544", "CVE-2014-1557", "CVE-2014-1558",
                "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1552");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-2296-1");

  tag_insight = "Christian Holler, David Keeler and Byron Campen discovered
multiple memory safety issues in Thunderbird. If a user were tricked in to
opening a specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-1547)

Atte Kettunen discovered a buffer overflow when interacting with WebAudio
buffers. If a user had enabled scripting, an attacker could potentially
exploit this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1549)

Atte Kettunen discovered a use-after-free in WebAudio. If a user had
enabled scripting, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1550)

Jethro Beekman discovered a use-after-free when the FireOnStateChange
event is triggered in some circumstances. If a user had enabled scripting,
an attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the priviliges of
the user invoking Thunderbird. (CVE-2014-1555)

Patrick Cozzi discovered a crash when using the Cesium JS library to
generate WebGL content. If a user had enabled scripting, an attacker could
potentially exploit this to execute arbitrary code with the privilges of
the user invoking Thunderbird. (CVE-2014-1556)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
CERT_DestroyCertificate. If a user had enabled scripting, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2014-1544)

A crash was discovered in Skia when scaling an image, if the scaling
operation takes too long. If a user had enabled scripting, an attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1557)

Christian Holler discovered several issues when parsing certificates
with non-standard character encoding, resulting in the inability to
use valid SSL certificates in some circumstances. (CVE-2014-1558,
CVE-2014-1559, CVE-2014-1560)

Boris Zbarsky discovered that network redirects could cause an iframe
to escape the confinements defined by its sandbox attribute in some
circumstances. If a user had enabled scripting, an attacker could
potentially exploit this to conduct cross-site scripting attacks.
(CVE-2014-1552)";

  tag_affected = "thunderbird on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2296-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2296-1/");
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:31.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:31.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
