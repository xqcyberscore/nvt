###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1244_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1244-1
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
tag_insight = "Dan Rosenberg discovered that the Linux kernel X.25 implementation
  incorrectly parsed facilities. A remote attacker could exploit this to
  crash the kernel, leading to a denial of service. (CVE-2010-3873)

  Andrea Righi discovered a race condition in the KSM memory merging support.
  If KSM was being used, a local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2011-2183)
  
  Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
  handled unlock requests. A local attacker could exploit this to cause a
  denial of service. (CVE-2011-2491)
  
  Vasiliy Kulikov discovered that taskstats did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2494)
  
  Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2495)
  
  It was discovered that the wireless stack incorrectly verified SSID
  lengths. A local attacker could exploit this to cause a denial of service
  or gain root privileges. (CVE-2011-2517)
  
  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)
  
  Christian Ohm discovered that the perf command looks for configuration
  files in the current directory. If a privileged user were tricked into
  running perf in a directory containing a malicious configuration file, an
  attacker could run arbitrary commands and possibly gain privileges.
  (CVE-2011-2905)
  
  Vasiliy Kulikov discovered that the Comedi driver did not correctly clear
  memory. A local attacker could exploit this to read kernel stack memory,
  leading to a loss of privacy. (CVE-2011-2909)
  
  Yogesh Sharma discovered that CIFS did not correctly handle UNCs that had
  no prefixpaths. A local attacker with access to a CIFS partition could
  exploit this to crash the system, leading to a denial of service.
  (CVE-2011-3363)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1244-1";
tag_affected = "linux-ti-omap4 on Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1244-1/");
  script_id(840787);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "USN", value: "1244-1");
  script_cve_id("CVE-2010-3873", "CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2494",
                "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2695", "CVE-2011-2905",
                "CVE-2011-2909", "CVE-2011-3363");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1244-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.26", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
