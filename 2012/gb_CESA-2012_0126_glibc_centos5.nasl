###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2012:0126 centos5 
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
tag_insight = "The glibc packages contain the standard C libraries used by multiple
  programs on the system. These packages contain the standard C and the
  standard math libraries. Without these two libraries, a Linux system cannot
  function properly.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the glibc library read timezone files. If a
  carefully-crafted timezone file was loaded by an application linked against
  glibc, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-5029)
  
  A flaw was found in the way the ldd utility identified dynamically linked
  libraries. If an attacker could trick a user into running ldd on a
  malicious binary, it could result in arbitrary code execution with the
  privileges of the user running ldd. (CVE-2009-5064)
  
  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the glibc library loaded ELF (Executable and Linking
  Format) files. If a carefully-crafted ELF file was loaded by an
  application linked against glibc, it could cause the application to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2010-0830)
  
  It was found that the glibc addmntent() function, used by various mount
  helper utilities, did not handle certain errors correctly when updating the
  mtab (mounted file systems table) file. If such utilities had the setuid
  bit set, a local attacker could use this flaw to corrupt the mtab file.
  (CVE-2011-1089)
  
  A denial of service flaw was found in the remote procedure call (RPC)
  implementation in glibc. A remote attacker able to open a large number of
  connections to an RPC service that is using the RPC implementation from
  glibc, could use this flaw to make that service use an excessive amount of
  CPU time. (CVE-2011-4609)
  
  Red Hat would like to thank the Ubuntu Security Team for reporting
  CVE-2010-0830, and Dan Rosenberg for reporting CVE-2011-1089. The Ubuntu
  Security Team acknowledges Dan Rosenberg as the original reporter of
  CVE-2010-0830.
  
  Users should upgrade to these updated packages, which resolve these issues.";

tag_affected = "glibc on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-February/018428.html");
  script_id(881084);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:03:45 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089",
                "CVE-2011-4609");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2012:0126");
  script_name("CentOS Update for glibc CESA-2012:0126 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.5~65.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
