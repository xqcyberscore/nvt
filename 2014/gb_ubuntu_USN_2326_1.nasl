###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2326_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for oxide-qt USN-2326-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841952");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-09-03 05:56:11 +0200 (Wed, 03 Sep 2014)");
  script_cve_id("CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3171", "CVE-2014-3173",
                "CVE-2014-3174", "CVE-2014-3175");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for oxide-qt USN-2326-1");

  tag_insight = "A use-after-free was discovered in the SVG implementation in
Blink. If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-3168)

A use-after-free was discovered in the DOM implementation in Blink. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-3169)

A use-after-free was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2014-3171)

It was discovered that WebGL clear calls did not interact properly with
the state of a draw buffer. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service. (CVE-2014-3173)

A threading issue was discovered in the Web Audio API during attempts to
update biquad filter coefficients. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service. (CVE-2014-3174)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3175)";

  tag_affected = "oxide-qt on Ubuntu 14.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2326-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2326-1/");
  script_summary("Check for the Version of oxide-qt");
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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.1.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:i386", ver:"1.1.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:i386", ver:"1.1.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
