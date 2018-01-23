###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1887_1.nasl 8494 2018-01-23 06:57:55Z teissa $
#
# Ubuntu Update for swift USN-1887-1
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
tag_insight = "Sebastian Krahmer discovered that Swift used the loads function in the
  pickle Python module when it was configured to use memcached. A remote
  attacker on the same network as memcached could exploit this to execute
  arbitrary code. This update adds a new memcache_serialization_support
  option to support secure json serialization. For details on this new
  option, please see /usr/share/doc/swift-proxy/memcache.conf-sample. This
  issue only affected Ubuntu 12.04 LTS. (CVE-2012-4406)

  Alex Gaynor discovered that Swift did not safely generate XML. An
  attacker could potentially craft an account name to generate arbitrary XML
  responses to trigger vulnerabilties in software parsing Swift's XML.
  (CVE-2013-2161)";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "swift on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_id(841485);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-06-24 15:06:42 +0530 (Mon, 24 Jun 2013)");
  script_cve_id("CVE-2012-4406", "CVE-2013-2161");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Ubuntu Update for swift USN-1887-1");

  script_xref(name: "USN", value: "1887-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1887-1/");
  script_tag(name: "summary" , value: "Check for the Version of swift");
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

  if ((res = isdpkgvuln(pkg:"python-swift", ver:"1.4.8-0ubuntu2.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-swift", ver:"1.7.4-0ubuntu2.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{
  ## Updated package version 1.8.0-0ubuntu1.2 to 1.8.0-0ubuntu1
  if ((res = isdpkgvuln(pkg:"python-swift", ver:"1.8.0-0ubuntu1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
