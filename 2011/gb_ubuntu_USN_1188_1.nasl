###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1188_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for ecryptfs-utils USN-1188-1
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
tag_insight = "Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
  validated permissions on the requested mountpoint. A local attacker could
  use this flaw to mount to arbitrary locations, leading to privilege
  escalation. (CVE-2011-1831)

  Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
  validated permissions on the requested mountpoint. A local attacker could
  use this flaw to unmount to arbitrary locations, leading to a denial of
  service. (CVE-2011-1832)
  
  Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
  validated permissions on the requested source directory. A local attacker
  could use this flaw to mount an arbitrary directory, possibly leading to
  information disclosure. A pending kernel update will provide the other
  half of the fix for this issue. (CVE-2011-1833)
  
  Dan Rosenberg and Marc Deslauriers discovered that eCryptfs incorrectly
  handled modifications to the mtab file when an error occurs. A local
  attacker could use this flaw to corrupt the mtab file, and possibly unmount
  arbitrary locations, leading to a denial of service. (CVE-2011-1834)
  
  Marc Deslauriers discovered that eCryptfs incorrectly handled keys when
  setting up an encrypted private directory. A local attacker could use this
  flaw to manipulate keys during creation of a new user. (CVE-2011-1835)
  
  Marc Deslauriers discovered that eCryptfs incorrectly handled permissions
  during recovery. A local attacker could use this flaw to possibly access
  another user's data during the recovery process. This issue only applied to
  Ubuntu 11.04. (CVE-2011-1836)
  
  Vasiliy Kulikov discovered that eCryptfs incorrectly handled lock counters.
  A local attacker could use this flaw to possibly overwrite arbitrary files.
  The default symlink restrictions in Ubuntu 10.10 and 11.04 should protect
  against this issue. (CVE-2011-1837)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1188-1";
tag_affected = "ecryptfs-utils on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1188-1/");
  script_id(840719);
  script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)");
  script_xref(name: "USN", value: "1188-1");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1836", "CVE-2011-1837");
  script_name("Ubuntu Update for ecryptfs-utils USN-1188-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-0ubuntu3.2.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-0ubuntu3.2.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"87-0ubuntu1.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
