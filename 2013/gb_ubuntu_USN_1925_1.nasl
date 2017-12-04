###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1925_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for thunderbird USN-1925-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841519);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:46:46 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-1701", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1713",
                "CVE-2013-1714", "CVE-2013-1717");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1925-1");

  tag_insight = "Jeff Gilbert and Henrik Skupin discovered multiple memory safety issues
in Thunderbird. If the user were tricked in to opening a specially crafted
message with scripting enabled, an attacker could possibly exploit these
to cause a denial of service via application crash, or potentially execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1701)

It was discovered that a document's URI could be set to the URI of
a different document. If a user had scripting enabled, an attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2013-1709)

A flaw was discovered when generating a CRMF request in certain
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks,
or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1710)

Cody Crews discovered that some Javascript components performed security
checks against the wrong URI, potentially bypassing same-origin policy
restrictions. If a user had scripting enabled, an attacker could exploit
this to conduct cross-site scripting (XSS) attacks or install addons
from a malicious site. (CVE-2013-1713)

Federico Lanusse discovered that web workers could bypass cross-origin
checks when using XMLHttpRequest. If a user had scripting enabled, an
attacker could potentially exploit this to conduct cross-site scripting
(XSS) attacks. (CVE-2013-1714)

Georgi Guninski and John Schoenick discovered that Java applets could
access local files under certain circumstances. If a user had scripting
enabled, an attacker could potentially exploit this to steal confidential
data. (CVE-2013-1717)";

  tag_affected = "thunderbird on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1925-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1925-1/");
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.8+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.8+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.8+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
