###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1154_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for openjdk-6 USN-1154-1
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
tag_insight = "It was discovered that a heap overflow in the AWT FileDialog.show()
  method could allow an attacker to cause a denial of service through an
  application crash or possibly execute arbitrary code. (CVE-2011-0815)

  It was discovered that integer overflows in the JPEGImageReader
  readImage() function and the SunLayoutEngine nativeLayout() function
  could allow an attacker to cause a denial of service through an
  application crash or possibly execute arbitrary code. (CVE-2011-0822,
  CVE-2011-0862)
  
  It was discovered that memory corruption could occur when interpreting
  bytecode in the HotSpot VM. This could allow an attacker to cause a
  denial of service through an application crash or possibly execute
  arbitrary code. (CVE-2011-0864)
  
  It was discovered that the deserialization code allowed the creation
  of mutable SignedObjects. This could allow an attacker to possibly
  execute code with elevated privileges. (CVE-2011-0865)
  
  It was discovered that the toString method in the NetworkInterface
  class would reveal multiple addresses if they were bound to the
  interface. This could give an attacker more information about the
  networking environment. (CVE-2011-0867)
  
  It was discovered that the Java 2D code to transform an image with a
  scale close to 0 could trigger an integer overflow. This could allow
  an attacker to cause a denial of service through an application crash
  or possibly execute arbitrary code. (CVE-2011-0868)
  
  It was discovered that the SOAP with Attachments API for Java (SAAJ)
  implementation allowed the modification of proxy settings via
  unprivileged SOAP messages. (CVE-2011-0869, CVE-2011-0870)
  
  It was the discovered that the Swing ImageIcon class created
  MediaTracker objects that potentially leaked privileged
  ApplicationContexts. This could possibly allow an attacker access to
  restricted resources or services. (CVE-2011-0871)
  
  It was discovered that non-blocking sockets marked as not urgent could
  still get selected for read operations. This could allow an attacker
  to cause a denial of service. (CVE-2011-0872)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1154-1";
tag_affected = "openjdk-6 on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1154-1/");
  script_id(840683);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1154-1");
  script_cve_id("CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0871", "CVE-2011-0872");
  script_name("Ubuntu Update for openjdk-6 USN-1154-1");

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

  if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
