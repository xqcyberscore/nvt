###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for python-keystoneclient USN-1851-1
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

tag_affected = "python-keystoneclient on Ubuntu 13.04";
tag_insight = "Eoghan Glynn and Alex Meade discovered that python-keystoneclient did not
  properly perform expiry checks for the PKI tokens used in Keystone. If
  Keystone were setup to use PKI tokens (the default in Ubuntu 13.04), a
  previously authenticated user could continue to use a PKI token for longer
  than intended.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841450);
  script_version("$Revision: 2931 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:12:09 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-06-04 09:20:23 +0530 (Tue, 04 Jun 2013)");
  script_cve_id("CVE-2013-2104");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_name("Ubuntu Update for python-keystoneclient USN-1851-1");

  script_xref(name: "USN", value: "1851-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-June/002135.html");
  script_summary("Check for the Version of python-keystoneclient");
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

if(release == "UBUNTU13.04")
{
  ## Changed package version from 1:0.2.3-0ubuntu2.2 to 1:0.2.3-0ubuntu2
  if ((res = isdpkgvuln(pkg:"python-keystoneclient", ver:"1:0.2.3-0ubuntu2", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
