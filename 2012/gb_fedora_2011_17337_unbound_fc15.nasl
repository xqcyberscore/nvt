###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for unbound FEDORA-2011-17337
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
tag_insight = "Unbound is a validating, recursive, and caching DNS(SEC) resolver.
  The C implementation of Unbound is developed and maintained by NLnet
  Labs. It is based on ideas and algorithms taken from a java prototype
  developed by Verisign labs, Nominet, Kirei and ep.net.

  Unbound is designed as a set of modular components, so that also
  DNSSEC (secure DNS) validation and stub-resolvers (that do not run
  as a server, but are linked into an application) are easily possible.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "unbound on Fedora 15";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-January/071535.html");
  script_id(863673);
  script_version("$Revision: 8336 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 08:01:48 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-01-09 12:53:03 +0530 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "FEDORA", value: "2011-17337");
  script_cve_id("CVE-2011-4528", "CVE-2011-1922", "CVE-2011-4869");
  script_name("Fedora Update for unbound FEDORA-2011-17337");

  script_tag(name: "summary" , value: "Check for the Version of unbound");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.4.14~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
