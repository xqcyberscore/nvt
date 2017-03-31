###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for acpid USN-1296-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Oliver-Tobias Ripka discovered that an ACPI script incorrectly handled power
  button events. A local attacker could use this to execute arbitrary code, and
  possibly escalate privileges. (CVE-2011-2777)

  Helmut Grohne and Michael Biebl discovered that ACPI scripts were executed with
  a permissive file mode creation mask (umask). A local attacker could read files
  and modify directories created by ACPI scripts that did not set a strict umask.
  (CVE-2011-4578)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1296-1";
tag_affected = "acpid on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-December/001515.html");
  script_id(840835);
  script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 3105 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:58:47 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-12-09 10:54:15 +0530 (Fri, 09 Dec 2011)");
  script_xref(name: "USN", value: "1296-1");
  script_cve_id("CVE-2011-2777", "CVE-2011-4578");
  script_name("Ubuntu Update for acpid USN-1296-1");

  script_summary("Check for the Version of acpid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"acpid", ver:"1.0.10-5ubuntu4.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"acpid", ver:"1.0.10-5ubuntu2.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"acpid", ver:"1:2.0.7-1ubuntu2.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
