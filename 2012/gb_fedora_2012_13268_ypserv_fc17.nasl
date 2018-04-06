###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ypserv FEDORA-2012-13268
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
tag_insight = "The Network Information Service (NIS) is a system that provides
  network information (login names, passwords, home directories, group
  information) to all of the machines on a network. NIS can allow users
  to log in on any machine on the network, as long as the machine has
  the NIS client programs running and the user's password is recorded in
  the NIS passwd database. NIS was formerly known as Sun Yellow Pages
  (YP).

  This package provides the NIS server, which will need to be running on
  your network. NIS clients do not need to be running the server.
  
  Install ypserv if you need an NIS server for your network. You also
  need to install the yp-tools and ypbind packages on any NIS client
  machines.";

tag_affected = "ypserv on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-September/087509.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864712");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-09-22 11:56:12 +0530 (Sat, 22 Sep 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-13268");
  script_name("Fedora Update for ypserv FEDORA-2012-13268");

  script_tag(name: "summary" , value: "Check for the Version of ypserv");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"ypserv", rpm:"ypserv~2.29~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
