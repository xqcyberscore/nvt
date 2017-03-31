###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for clamav vulnerabilities USN-926-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "It was discovered that ClamAV did not properly verify its input when
  processing CAB files. A remote attacker could send a specially crafted
  CAB file to evade malware detection. (CVE-2010-0098)

  It was discovered that ClamAV did not properly verify its input when
  processing CAB files. A remote attacker could send a specially crafted
  CAB file and cause a denial of service via application crash.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-926-1";
tag_affected = "clamav vulnerabilities on Ubuntu 8.10 ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2010-April/001073.html");
  script_id(840413);
  script_version("$Revision: 5387 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:10:31 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-04-09 11:11:25 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "926-1");
  script_cve_id("CVE-2010-0098");
  script_name("Ubuntu Update for clamav vulnerabilities USN-926-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.95.3+dfsg-1ubuntu0.09.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.95.3+dfsg-1ubuntu0.09.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.95.3+dfsg-1ubuntu0.09.04~intrepid3", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
