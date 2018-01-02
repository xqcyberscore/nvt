###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for clamav FEDORA-2011-15033
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
tag_affected = "clamav on Fedora 16";
tag_insight = "Clam AntiVirus is an anti-virus toolkit for UNIX. The main purpose of this
  software is the integration with mail servers (attachment scanning). The
  package provides a flexible and scalable multi-threaded daemon, a command
  line scanner, and a tool for automatic updating via Internet. The programs
  are based on a shared library distributed with the Clam AntiVirus package,
  which you can use with your own software. The virus database is based on
  the virus database from OpenAntiVirus, but contains additional signatures
  (including signatures for popular polymorphic viruses, too) and is KEPT UP
  TO DATE.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-November/068942.html");
  script_id(864011);
  script_version("$Revision: 8245 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 07:29:59 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-04-02 12:54:26 +0530 (Mon, 02 Apr 2012)");
  script_cve_id("CVE-2011-3627", "CVE-2011-2721");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2011-15033");
  script_name("Fedora Update for clamav FEDORA-2011-15033");

  script_tag(name: "summary" , value: "Check for the Version of clamav");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.97.3~1600.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
