###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xen FEDORA-2012-18249
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
tag_affected = "xen on Fedora 16";
tag_insight = "This package contains the XenD daemon and xm command line
  tools, needed to manage virtual machines running under the
  Xen hypervisor";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-November/092624.html");
  script_id(864875);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-11-23 11:33:49 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538",
                "CVE-2012-4539", "CVE-2012-4544", "CVE-2012-3494", "CVE-2012-3495",
                "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411",
                "CVE-2012-3433", "CVE-2012-3432", "CVE-2012-2625", "CVE-2012-0217",
                "CVE-2012-0218", "CVE-2012-2934", "CVE-2012-0029");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-18249");
  script_name("Fedora Update for xen FEDORA-2012-18249");

  script_tag(name: "summary" , value: "Check for the Version of xen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.3~4.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
