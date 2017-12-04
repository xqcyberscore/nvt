###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1187_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux-lts-backport-maverick USN-1187-1
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
tag_insight = "It was discovered that KVM did not correctly initialize certain CPU
  registers. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2010-3698)

  Thomas Pollet discovered that the RDS network protocol did not check
  certain iovec buffers. A local attacker could exploit this to crash the
  system or possibly execute arbitrary code as the root user. (CVE-2010-3865)
  
  Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
  not correctly clear kernel memory. A local attacker could exploit this to
  read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)
  
  Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
  not properly initialize certain structures. A local attacker could exploit
  this to read kernel stack memory, leading to a loss of privacy.
  (CVE-2010-3876)
  
  Vasiliy Kulikov discovered that the TIPC interface did not correctly
  initialize certain structures. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)
  
  Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
  properly audit certain bytecodes in netlink messages. A local attacker
  could exploit this to cause the kernel to hang, leading to a denial of
  service. (CVE-2010-3880)
  
  Vasiliy Kulikov discovered that kvm did not correctly clear memory. A local
  attacker could exploit this to read portions of the kernel stack, leading
  to a loss of privacy. (CVE-2010-3881)
  
  Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)
  
  Dan Rosenberg discovered that the ivtv V4L driver did not correctly
  initialize certain structures. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-4079)
  
  Dan Rosenberg discovered that the semctl syscall did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4083)
  
  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163, CVE-2010-4668)
  
  It was discovered that multithreaded exec did not handle CPU timers
  correctly. A local attac ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1187-1";
tag_affected = "linux-lts-backport-maverick on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1187-1/");
  script_id(840718);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "USN", value: "1187-1");
  script_cve_id("CVE-2010-3698", "CVE-2010-3865", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3881", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4163", "CVE-2010-4668", "CVE-2010-4248", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2011-1044", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2534", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746");
  script_name("Ubuntu Update for linux-lts-backport-maverick USN-1187-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.56~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.56~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.56~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.56~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
