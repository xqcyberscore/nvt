###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1192_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for firefox USN-1192-1
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
tag_insight = "Aral Yaman discovered a vulnerability in the WebGL engine. An attacker
  could potentially use this to crash Firefox or execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2989)

  Vivekanand Bolajwar discovered a vulnerability in the JavaScript engine. An
  attacker could potentially use this to crash Firefox or execute arbitrary
  code with the privileges of the user invoking Firefox. (CVE-2011-2991)
  
  Bert Hubert and Theo Snelleman discovered a vulnerability in the Ogg
  reader. An attacker could potentially use this to crash Firefox or execute
  arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2991)
  
  Robert Kaiser, Jesse Ruderman, Gary Kwong, Christoph Diehl, Martijn
  Wargers, Travis Emmitt, Bob Clary, and Jonathan Watt discovered multiple
  memory vulnerabilities in the browser rendering engine. An attacker could
  use these to possibly execute arbitrary code with the privileges of the
  user invoking Firefox. (CVE-2011-2985)
  
  Rafael Gieschke discovered that unsigned JavaScript could call into a
  script inside a signed JAR. This could allow an attacker to execute
  arbitrary code with the identity and permissions of the signed JAR.
  (CVE-2011-2993)
  
  Michael Jordon discovered that an overly long shader program could cause a
  buffer overrun. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2988)
  
  Michael Jordon discovered a heap overflow in the ANGLE library used in
  Firefox's WebGL implementation. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2987)
  
  It was discovered that an SVG text manipulation routine contained a
  dangling pointer vulnerability. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-0084)
  
  Mike Cardwell discovered that Content Security Policy violation reports
  failed to strip out proxy authorization credentials from the list of
  request headers. This could allow a malicious website to capture proxy
  authorization credentials. Daniel Veditz discovered that redirecting to a
  website with Content Security Policy resulted in the incorrect resolution
  of hosts in the constructed policy. This could allow a malicious website to
  circumvent the Content Security Policy of another website. (CVE-2011-2990)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1192-1";
tag_affected = "firefox on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1192-1/");
  script_id(840724);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1192-1");
  script_cve_id("CVE-2011-2989", "CVE-2011-2991", "CVE-2011-2985", "CVE-2011-2993", "CVE-2011-2988", "CVE-2011-2987", "CVE-2011-0084", "CVE-2011-2990", "CVE-2011-2992");
  script_name("Ubuntu Update for firefox USN-1192-1");

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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"6.0+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
