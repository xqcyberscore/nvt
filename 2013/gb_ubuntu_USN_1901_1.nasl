###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for raptor2 USN-1901-1
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

tag_affected = "raptor2 on Ubuntu 12.04 LTS";
tag_insight = "Timothy D. Morgan discovered that Raptor would unconditionally load XML
  external entities. If a user were tricked into opening a specially crafted
  document in an application linked against Raptor, an attacker could
  possibly obtain access to arbitrary files on the user's system or
  potentially execute arbitrary code with the privileges of the user invoking
  the program.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841501);
  script_version("$Revision: 2932 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:15:28 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-07-09 15:51:04 +0530 (Tue, 09 Jul 2013)");
  script_cve_id("CVE-2012-0037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Ubuntu Update for raptor2 USN-1901-1");

  script_xref(name: "USN", value: "1901-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-July/002186.html");
  script_summary("Check for the Version of raptor2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isdpkgvuln(pkg:"libraptor2-0", ver:"2.0.6-1ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
