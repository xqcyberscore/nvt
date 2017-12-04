###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1952_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for thunderbird USN-1952-1
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
  script_id(841555);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:48:10 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-1718", "CVE-2013-1720", "CVE-2013-1721", "CVE-2013-1722",
                "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730",
                "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737",
                "CVE-2013-1738");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1952-1");

  tag_insight = "Multiple memory safety issues were discovered in Thunderbird. If a user
were tricked in to opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1718)

Atte Kettunen discovered a flaw in the HTML5 Tree Builder when interacting
with template elements. If a user had scripting enabled, in some
circumstances an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1720)

Alex Chapman discovered an integer overflow vulnerability in the ANGLE
library. If a user had scripting enabled, an attacker could potentially
exploit this to execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2013-1721)

Abhishek Arya discovered a use-after-free in the Animation Manager. If
a user had scripting enabled, an attacked could potentially exploit this
to execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1722)

Scott Bell discovered a use-after-free when using a select element. If
a user had scripting enabled, an attacker could potentially exploit this
to execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1724)

It was discovered that the scope of new Javascript objects could be
accessed before their compartment is initialized. If a user had scripting
enabled, an attacker could potentially exploit this to execute code with
the privileges of the user invoking Thunderbird. (CVE-2013-1725)

Dan Gohman discovered that some variables and data were used in IonMonkey,
without being initialized, which could lead to information leakage.
(CVE-2013-1728)

Sachin Shinde discovered a crash when moving some XBL-backed nodes
in to a document created by document.open(). If a user had scripting
enabled, an attacker could potentially exploit this to cause a denial
of service. (CVE-2013-1730)

Aki Helin discovered a buffer overflow when combining lists, floats and
multiple columns. If a user had scripting enabled, an attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-1732)

Two memory corruption bugs when scrolling were discovered. If a user had
scripting enabled, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-201 ... 

  Description truncated, for more information please check the Reference URL";

  tag_affected = "thunderbird on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1952-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1952-1/");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
