###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1362-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
  who can mount a FUSE file system could cause a denial of service.
  (CVE-2011-3353)

  A flaw was found in KVM's Programmable Interval Timer (PIT). When a virtual
  interrupt control is not available a local user could use this to cause a
  denial of service by starting a timer. (CVE-2011-4622)

  A flaw was discovered in the XFS filesystem. If a local user mounts a
  specially crafted XFS image it could potential execute arbitrary code on
  the system. (CVE-2012-0038)

  Chen Haogang discovered an integer overflow that could result in memory
  corruption. A local unprivileged user could use this to crash the system.
  (CVE-2012-0044)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1362-1";
tag_affected = "linux on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-February/001587.html");
  script_id(840893);
  script_version("$Revision: 5963 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:58:55 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-3353", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0044");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1362-1");
  script_name("Ubuntu Update for linux USN-1362-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-generic", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-generic-pae", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-omap", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-powerpc", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-powerpc-smp", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-powerpc64-smp", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-server", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-versatile", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-13-virtual", ver:"2.6.38-13.55", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
