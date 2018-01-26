###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2013-6041
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

tag_affected = "kernel on Fedora 18";
tag_insight = "The kernel package contains the Linux kernel (vmlinuz), the core of any
  Linux operating system.  The kernel handles the basic functions
  of the operating system: memory allocation, process allocation, device
  input and output, etc.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865576);
  script_version("$Revision: 8526 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 07:57:37 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-04-22 10:28:49 +0530 (Mon, 22 Apr 2013)");
  script_cve_id("CVE-2013-1929", "CVE-2013-1873", "CVE-2013-1796", "CVE-2013-1797",
                "CVE-2013-1798", "CVE-2013-1860", "CVE-2013-0913", "CVE-2013-0914",
                "CVE-2013-1828", "CVE-2013-1792", "CVE-2013-1767", "CVE-2013-1763",
                "CVE-2013-0290", "CVE-2013-0228", "CVE-2013-0190");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for kernel FEDORA-2013-6041");

  script_xref(name: "FEDORA", value: "2013-6041");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/102104.html");
  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.8.8~202.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
