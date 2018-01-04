###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ipmitool FEDORA-2011-17071
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
tag_insight = "This package contains a utility for interfacing with devices that support
  the Intelligent Platform Management Interface specification.  IPMI is
  an open standard for machine health, inventory, and remote power control.

  This utility can communicate with IPMI-enabled devices through either a
  kernel driver such as OpenIPMI or over the RMCP LAN protocol defined in
  the IPMI specification.  IPMIv2 adds support for encrypted LAN
  communications and remote Serial-over-LAN functionality.

  It provides commands for reading the Sensor Data Repository (SDR) and
  displaying sensor values, displaying the contents of the System Event
  Log (SEL), printing Field Replaceable Unit (FRU) information, reading and
  setting LAN configuration, and chassis power control.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "ipmitool on Fedora 15";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-January/071575.html");
  script_id(863674);
  script_version("$Revision: 8273 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 07:29:19 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-01-09 12:53:08 +0530 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2011-17071");
  script_cve_id("CVE-2011-4339");
  script_name("Fedora Update for ipmitool FEDORA-2011-17071");

  script_tag(name: "summary" , value: "Check for the Version of ipmitool");
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

  if ((res = isrpmvuln(pkg:"ipmitool", rpm:"ipmitool~1.8.11~7.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
