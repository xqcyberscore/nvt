###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for indicator-datetime USN-2186-1
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
  script_id(841800);
  script_version("$Revision: 2810 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-09 12:41:27 +0100 (Wed, 09 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-05-05 11:25:19 +0530 (Mon, 05 May 2014)");
  script_cve_id("CVE-2013-7374");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for indicator-datetime USN-2186-1");

  tag_insight = "It was discovered that the Date and Time Indicator incorrectly
allowed Evolution to be opened at the greeter screen. An attacker could use this
issue to possibly gain unexpected access to applications such as a web
browser with privileges of the greeter user.";

  tag_affected = "indicator-datetime on Ubuntu 13.10";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2186-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-April/002483.html");
  script_summary("Check for the Version of indicator-datetime");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"indicator-datetime", ver:"13.10.0+13.10.20131023.2-0ubuntu1.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
