###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2348_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for apt USN-2348-1
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841969");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-09-17 05:58:42 +0200 (Wed, 17 Sep 2014)");
  script_cve_id("CVE-2014-0487", "CVE-2014-0488", "CVE-2014-0489", "CVE-2014-0490");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for apt USN-2348-1");
  script_tag(name: "insight", value: "It was discovered that APT did not
re-verify downloaded files when the If-Modified-Since wasn't met. (CVE-2014-0487)

It was discovered that APT did not invalidate repository data when it
switched from an unauthenticated to an authenticated state. (CVE-2014-0488)

It was discovered that the APT Acquire::GzipIndexes option caused APT to
skip checksum validation. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS, and was not enabled by default. (CVE-2014-0489)

It was discovered that APT did not correctly validate signatures when
downloading source packages using the download command. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-0490)");
  script_tag(name: "affected", value: "apt on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "USN", value: "2348-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2348-1/");
  script_summary("Check for the Version of apt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apt", ver:"1.0.1ubuntu2.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apt", ver:"0.8.16~exp12ubuntu10.19", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apt", ver:"0.7.25.3ubuntu9.16", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
