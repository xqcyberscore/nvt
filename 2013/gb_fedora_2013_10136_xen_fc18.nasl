###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xen FEDORA-2013-10136
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

tag_solution = "Please Install the Updated Packages.";
tag_insight = "This package contains the XenD daemon and xm command line
  tools, needed to manage virtual machines running under the
  Xen hypervisor";
tag_affected = "xen on Fedora 18";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_id(865902);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-06-18 10:31:10 +0530 (Tue, 18 Jun 2013)");
  script_cve_id("CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2072",
                "CVE-2013-1918", "CVE-2013-1952", "CVE-2013-1922", "CVE-2013-1919",
                "CVE-2013-1917", "CVE-2013-1920", "CVE-2013-0153", "CVE-2013-0215",
                "CVE-2013-0151", "CVE-2013-0152", "CVE-2012-6075", "CVE-2012-5634",
                                                                   "CVE-2013-0154");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Fedora Update for xen FEDORA-2013-10136");

  script_xref(name: "FEDORA", value: "2013-10136");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108918.html");
  script_tag(name: "summary" , value: "Check for the Version of xen");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.2~6.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
