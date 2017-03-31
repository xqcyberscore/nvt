###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for cups USN-2144-1
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
  script_id(841753);
  script_version("$Revision: 2810 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-09 12:41:27 +0100 (Wed, 09 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-03-17 13:43:12 +0530 (Mon, 17 Mar 2014)");
  script_cve_id("CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for cups USN-2144-1");

  tag_insight = "Florian Weimer discovered that the pdftoopvp filter bundled
in the CUPS package incorrectly handled memory. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6474, CVE-2013-6475)

Florian Weimer discovered that the pdftoopvp filter bundled in the CUPS
package did not restrict driver directories. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6476)";

  tag_affected = "cups on Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2144-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-March/002438.html");
  script_summary("Check for the Version of cups");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"cups", ver:"1.4.3-1ubuntu1.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
