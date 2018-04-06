###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for net-snmp FEDORA-2012-16662
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
tag_insight = "SNMP (Simple Network Management Protocol) is a protocol used for
  network management. The NET-SNMP project includes various SNMP tools:
  an extensible agent, an SNMP library, tools for requesting or setting
  information from SNMP agents, tools for generating and handling SNMP
  traps, a version of the netstat command which uses SNMP, and a Tk/Perl
  mib browser. This package contains the snmpd and snmptrapd daemons,
  documentation, etc.

  You will probably also want to install the net-snmp-utils package,
  which contains NET-SNMP utilities.";

tag_affected = "net-snmp on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-October/090964.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864834");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 10:59:20 +0530 (Fri, 02 Nov 2012)");
  script_cve_id("CVE-2012-2141");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2012-16662");
  script_name("Fedora Update for net-snmp FEDORA-2012-16662");

  script_tag(name: "summary" , value: "Check for the Version of net-snmp");
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

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.1~5.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
