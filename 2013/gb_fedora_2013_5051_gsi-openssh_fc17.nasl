###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gsi-openssh FEDORA-2013-5051
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
tag_insight = "SSH (Secure SHell) is a program for logging into and executing
  commands on a remote machine. SSH is intended to replace rlogin and
  rsh, and to provide secure encrypted communications between two
  untrusted hosts over an insecure network. X11 connections and
  arbitrary TCP/IP ports can also be forwarded over the secure channel.

  OpenSSH is OpenBSD's version of the last free version of SSH, bringing
  it up to date in terms of security and features.

  This version of OpenSSH has been modified to support GSI authentication.

  This package includes the core files necessary for both the gsissh
  client and server. To make this package useful, you should also
  install gsi-openssh-clients, gsi-openssh-server, or both.";


tag_affected = "gsi-openssh on Fedora 17";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.865566");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-19 09:48:41 +0530 (Fri, 19 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for gsi-openssh FEDORA-2013-5051");

  script_xref(name: "FEDORA", value: "2013-5051");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101930.html");
  script_tag(name:"summary", value:"Check for the Version of gsi-openssh");
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

  if ((res = isrpmvuln(pkg:"gsi-openssh", rpm:"gsi-openssh~5.9p1~11.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
