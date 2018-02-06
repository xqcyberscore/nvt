###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1802_1.nasl 8672 2018-02-05 16:39:18Z teissa $
#
# Ubuntu Update for samba USN-1802-1
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

tag_affected = "samba on Ubuntu 12.04 LTS";
tag_insight = "It was discovered that Samba incorrectly handled CIFS share attributes when
  SMB2 was used. A remote authenticated user could possibly gain write access
  to certain shares, bypassing the intended permissions.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841403);
  script_version("$Revision: 8672 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:39:18 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-04-19 10:09:06 +0530 (Fri, 19 Apr 2013)");
  script_cve_id("CVE-2013-0454");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_name("Ubuntu Update for samba USN-1802-1");

  script_xref(name: "USN", value: "1802-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1802-1/");
  script_tag(name: "summary" , value: "Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.6.3-2ubuntu2.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
