###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1129_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for perl USN-1129-1
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
tag_insight = "It was discovered that the Safe.pm Perl module incorrectly handled
  Safe::reval and Safe::rdo access restrictions. An attacker could use this
  flaw to bypass intended restrictions and possibly execute arbitrary code.
  (CVE-2010-1168, CVE-2010-1447)

  It was discovered that the CGI.pm Perl module incorrectly handled certain
  MIME boundary strings. An attacker could use this flaw to inject arbitrary
  HTTP headers and perform HTTP response splitting and cross-site scripting
  attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
  10.10. (CVE-2010-2761, CVE-2010-4411)
  
  It was discovered that the CGI.pm Perl module incorrectly handled newline
  characters. An attacker could use this flaw to inject arbitrary HTTP
  headers and perform HTTP response splitting and cross-site scripting
  attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
  10.10. (CVE-2010-4410)
  
  It was discovered that the lc, lcfirst, uc, and ucfirst functions did not
  properly apply the taint attribute when processing tainted input. An
  attacker could use this flaw to bypass intended restrictions. This issue
  only affected Ubuntu 8.04 LTS, 10.04 LTS and 10.10. (CVE-2011-1487)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1129-1";
tag_affected = "perl on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 6.06 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1129-1/");
  script_id(840647);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1129-1");
  script_cve_id("CVE-2010-1168", "CVE-2010-1447", "CVE-2010-2761", "CVE-2010-4411", "CVE-2010-4410", "CVE-2011-1487");
  script_name("Ubuntu Update for perl USN-1129-1");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-8ubuntu2.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.8.7-10ubuntu1.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.8.8-12ubuntu0.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-17ubuntu4.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-12ubuntu2.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
