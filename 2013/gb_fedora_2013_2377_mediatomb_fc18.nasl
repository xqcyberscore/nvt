###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mediatomb FEDORA-2013-2377
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
tag_insight = "MediaTomb is an open source (GPL) UPnP MediaServer with a nice web user
  interface, it allows you to stream your digital media through your home
  network and listen to/watch it on a variety of UPnP compatible devices.

  MediaTomb implements the UPnP MediaServer V 1.0 specification that can
  be found on <A HREF= &qt http://www.upnp.org/. &qt >http://www.upnp.org/.</A>";


tag_affected = "mediatomb on Fedora 18";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/099022.html");
  script_oid("1.3.6.1.4.1.25623.1.0.865371");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 09:59:05 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960", "CVE-2012-5961",
                "CVE-2012-5962", "CVE-2012-5963", "CVE-2012-5964", "CVE-2012-5965");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2013-2377");
  script_name("Fedora Update for mediatomb FEDORA-2013-2377");

  script_tag(name: "summary" , value: "Check for the Version of mediatomb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"mediatomb", rpm:"mediatomb~0.12.1~23.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
