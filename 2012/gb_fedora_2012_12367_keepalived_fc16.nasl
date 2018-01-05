###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for keepalived FEDORA-2012-12367
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
tag_affected = "keepalived on Fedora 16";
tag_insight = "The main goal of the keepalived project is to add a strong &amp; robust keepalive
  facility to the Linux Virtual Server project. This project is written in C with
  multilayer TCP/IP stack checks. Keepalived implements a framework based on
  three family checks : Layer3, Layer4 &amp; Layer5/7. This framework gives the
  daemon the ability to check the state of an LVS server pool. When one of the
  servers of the LVS server pool is down, keepalived informs the linux kernel via
  a setsockopt call to remove this server entry from the LVS topology. In
  addition keepalived implements an independent VRRPv2 stack to handle director
  failover. So in short keepalived is a userspace daemon for LVS cluster nodes
  healthchecks and LVS directors failover.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-September/085972.html");
  script_id(864694);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-09-07 11:25:23 +0530 (Fri, 07 Sep 2012)");
  script_cve_id("CVE-2011-1784");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-12367");
  script_name("Fedora Update for keepalived FEDORA-2012-12367");

  script_tag(name: "summary" , value: "Check for the Version of keepalived");
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

  if ((res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~1.2.3~2.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}