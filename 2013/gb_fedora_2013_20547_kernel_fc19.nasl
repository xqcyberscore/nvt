###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2013-20547
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867043");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:34:57 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2013-4348", "CVE-2013-4470", "CVE-2013-4387", "CVE-2013-4345",
                "CVE-2013-4350", "CVE-2013-4343", "CVE-2013-2888", "CVE-2013-2889",
                "CVE-2013-2891", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2894",
                "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899",
                "CVE-2013-0343", "CVE-2013-4254", "CVE-2013-4125", "CVE-2013-2232",
                "CVE-2013-1059", "CVE-2013-2234");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Update for kernel FEDORA-2013-20547");

  tag_insight = "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.
";

  tag_affected = "kernel on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-20547");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-November/120093.html");
  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.11.6~201.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
