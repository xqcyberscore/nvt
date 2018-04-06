###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for nas FEDORA-2013-17036
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.866944");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:14:43 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2013-4256", "CVE-2013-4257", "CVE-2013-4258");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for nas FEDORA-2013-17036");

  tag_insight = "In a nutshell, NAS is the audio equivalent of an X display  server.
The Network Audio System (NAS) was developed by NCD for playing,
recording, and manipulating audio data over a network.  Like the
X Window System, it uses the client/server model to separate
applications from the specific drivers that control audio input
and output devices.
Key features of the Network Audio System include:
    o  Device-independent audio over the network
    o  Lots of audio file and data formats
    o  Can store sounds in server for rapid replay
    o  Extensive mixing, separating, and manipulation of audio data
    o  Simultaneous use of audio devices by multiple applications
    o  Use by a growing number of ISVs
    o  Small size
    o  Free!  No obnoxious licensing terms
";

  tag_affected = "nas on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-17036");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-September/117049.html");
  script_tag(name: "summary" , value: "Check for the Version of nas");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"nas", rpm:"nas~1.9.3~7.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
