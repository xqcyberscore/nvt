###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for tor FEDORA-2012-14650
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
tag_insight = "Tor is a connection-based low-latency anonymous communication system.

  Applications connect to the local Tor proxy using the SOCKS protocol. The
  local proxy chooses a path through a set of relays, in which each relay
  knows its predecessor and successor, but no others. Traffic flowing down
  the circuit is unwrapped by a symmetric key at each relay, which reveals
  the downstream relay.

  Warnings: Tor does no protocol cleaning.  That means there is a danger
  that application protocols and associated programs can be induced to
  reveal information about the initiator. Tor depends on Privoxy and
  similar protocol cleaners to solve this problem. This is alpha code,
  and is even more likely than released code to have anonymity-spoiling
  bugs. The present network is very small -- this further reduces the
  strength of the anonymity provided. Tor is not presently suitable for
  high-stakes anonymity.";


tag_affected = "tor on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098157.html");
  script_id(865300);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:52:54 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2012-4419", "CVE-2012-4422", "CVE-2012-4922", "CVE-2012-3517");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2012-14650");
  script_name("Fedora Update for tor FEDORA-2012-14650");

  script_tag(name: "summary" , value: "Check for the Version of tor");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.2.39~1700.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
