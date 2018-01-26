###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for nagios-plugins FEDORA-2013-8935
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

tag_affected = "nagios-plugins on Fedora 18";
tag_insight = "Nagios is a program that will monitor hosts and services on your
  network, and to email or page you when a problem arises or is
  resolved. Nagios runs on a Unix server as a background or daemon
  process, intermittently running checks on various services that you
  specify. The actual service checks are performed by separate plugin
  programs which return the status of the checks to Nagios. This package
  contains those plugins.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865685);
  script_version("$Revision: 8526 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 07:57:37 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-06-04 09:18:20 +0530 (Tue, 04 Jun 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for nagios-plugins FEDORA-2013-8935");

  script_xref(name: "FEDORA", value: "2013-8935");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-June/107202.html");
  script_tag(name: "summary" , value: "Check for the Version of nagios-plugins");
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

  if ((res = isrpmvuln(pkg:"nagios-plugins", rpm:"nagios-plugins~1.4.16~7.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
