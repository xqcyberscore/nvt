###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xen FEDORA-2013-21041
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(867075);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:41:55 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-4551", "CVE-2013-4494", "CVE-2013-4416", "CVE-2013-4368",
                "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375",
                "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-1442", "CVE-2013-4329",
                "CVE-2013-1918", "CVE-2013-1432", "CVE-2013-2211", "CVE-2013-2194",
                "CVE-2013-2195", "CVE-2013-2196");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Fedora Update for xen FEDORA-2013-21041");

  tag_insight = "This package contains the XenD daemon and xm command line
tools, needed to manage virtual machines running under the
Xen hypervisor
";

  tag_affected = "xen on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-21041");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122294.html");
  script_tag(name: "summary" , value: "Check for the Version of xen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.3~8.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
