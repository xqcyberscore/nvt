###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1878_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux USN-1878-1
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
tag_insight = "An information leak was discovered in the Linux kernel when inotify is used
  to monitor the /dev/ptmx device. A local user could exploit this flaw to
  discover keystroke timing and potentially discover sensitive information
  like password length. (CVE-2013-0160)

  A flaw was discovered in the Linux kernel's perf events subsystem for Intel
  Sandy Bridge and Ivy Bridge processors. A local user could exploit this
  flaw to cause a denial of service (system crash). (CVE-2013-2146)

  An information leak was discovered in the Linux kernel's crypto API. A
  local user could exploit this flaw to examine potentially sensitive
  information from the kernel's stack memory. (CVE-2013-3076)

  An information leak was discovered in the Linux kernel's rcvmsg path for
  ATM (Asynchronous Transfer Mode). A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3222)

  An information leak was discovered in the Linux kernel's recvmsg path for
  ax25 address family. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3223)

  An information leak was discovered in the Linux kernel's recvmsg path for
  the bluetooth address family. A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3224)

  An information leak was discovered in the Linux kernel's bluetooth rfcomm
  protocol support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3225)

  An information leak was discovered in the Linux kernel's CAIF protocol
  implementation. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3227)

  An information leak was discovered in the Linux kernel's IRDA (infrared)
  support subsystem. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3228)

  An information leak was discovered in the Linux kernel's s390 - z/VM
  support. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3229)

  An information leak was discovered in the Linux kernel's llc (Logical Link
  Layer 2) support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3231)

  An information leak was discovered in the Linux kernel's receiv ...

  Description truncated, for more information please check the Reference URL";


tag_affected = "linux on Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841473);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-06-18 10:41:07 +0530 (Tue, 18 Jun 2013)");
  script_cve_id("CVE-2013-0160", "CVE-2013-2146", "CVE-2013-3076", "CVE-2013-3222",
                "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227",
                "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232",
                "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Ubuntu Update for linux USN-1878-1");

  script_xref(name: "USN", value: "1878-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1878-1/");
  script_summary("Check for the Version of linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-generic", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-generic-pae", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-highbank", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-omap", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-powerpc-smp", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-powerpc64-smp", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-48-virtual", ver:"3.2.0-48.74", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
