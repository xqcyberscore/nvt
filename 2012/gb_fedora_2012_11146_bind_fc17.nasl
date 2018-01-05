###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for bind FEDORA-2012-11146
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
tag_affected = "bind on Fedora 17";
tag_insight = "BIND (Berkeley Internet Name Domain) is an implementation of the DNS
  (Domain Name System) protocols. BIND includes a DNS server (named),
  which resolves host names to IP addresses; a resolver library
  (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating properly.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-August/084813.html");
  script_id(864621);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 10:38:33 +0530 (Thu, 30 Aug 2012)");
  script_cve_id("CVE-2012-3817", "CVE-2012-3868", "CVE-2012-1667");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_xref(name: "FEDORA", value: "2012-11146");
  script_name("Fedora Update for bind FEDORA-2012-11146");

  script_tag(name: "summary" , value: "Check for the Version of bind");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.1~5.P2.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
