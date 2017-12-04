###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1119_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1119-1
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
tag_insight = "Dan Rosenberg discovered that the RDS network protocol did not correctly
  check certain parameters. A local attacker could exploit this gain root
  privileges. (CVE-2010-3904)

  Nelson Elhage discovered several problems with the Acorn Econet protocol
  driver. A local user could cause a denial of service via a NULL pointer
  dereference, escalate privileges by overflowing the kernel stack, and
  assign Econet addresses to arbitrary interfaces. (CVE-2010-3848,
  CVE-2010-3849, CVE-2010-3850)
  
  Ben Hawkes discovered that the Linux kernel did not correctly validate
  memory ranges on 64bit kernels when allocating memory on behalf of 32bit
  system calls. On a 64bit system, a local attacker could perform malicious
  multicast getsockopt calls to gain root privileges. (CVE-2010-3081)
  
  Tavis Ormandy discovered that the IRDA subsystem did not correctly shut
  down. A local attacker could exploit this to cause the system to crash or
  possibly gain root privileges. (CVE-2010-2954)
  
  Brad Spengler discovered that the wireless extensions did not correctly
  validate certain request sizes. A local attacker could exploit this to read
  portions of kernel memory, leading to a loss of privacy. (CVE-2010-2955)
  
  Tavis Ormandy discovered that the session keyring did not correctly check
  for its parent. On systems without a default session keyring, a local
  attacker could exploit this to crash the system, leading to a denial of
  service. (CVE-2010-2960)
  
  Kees Cook discovered that the Intel i915 graphics driver did not correctly
  validate memory regions. A local attacker with access to the video card
  could read and write arbitrary kernel memory to gain root privileges.
  (CVE-2010-2962)
  
  Kees Cook discovered that the V4L1 32bit compat interface did not correctly
  validate certain parameters. A local attacker on a 64bit system with access
  to a video device could exploit this to gain root privileges.
  (CVE-2010-2963)
  
  Robert Swiecki discovered that ftrace did not correctly handle mutexes. A
  local attacker could exploit this to crash the kernel, leading to a denial
  of service. (CVE-2010-3079)
  
  Tavis Ormandy discovered that the OSS sequencer device did not correctly
  shut down. A local attacker could exploit this to crash the system or
  possibly gain root privileges. (CVE-2010-3080)
  
  Dan Rosenberg discovered that the CD driver did not correctly check
  parameters. A local attacker could exploit this to read arbitrary kernel
  memory, leading to a loss of privacy. (CVE-2010-3437)
  
  Dan Rosenberg discovered that SCTP did not correctly handle HMAC
  calcu ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1119-1";
tag_affected = "linux-ti-omap4 on Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1119-1/");
  script_id(840651);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1119-1");
  script_cve_id("CVE-2010-3904", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3081", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3437", "CVE-2010-3705", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-4072", "CVE-2010-4079", "CVE-2010-4158", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4249", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1119-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.22", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
