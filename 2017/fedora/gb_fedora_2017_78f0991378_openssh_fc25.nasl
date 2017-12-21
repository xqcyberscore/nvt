###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_78f0991378_openssh_fc25.nasl 8203 2017-12-21 05:55:19Z cfischer $
#
# Fedora Update for openssh FEDORA-2017-78f0991378
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873905");
  script_version("$Revision: 8203 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 06:55:19 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-14 11:43:06 +0100 (Thu, 14 Dec 2017)");
  script_cve_id("CVE-2017-15906");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openssh FEDORA-2017-78f0991378");
  script_tag(name: "summary", value: "Check the version of openssh");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "SSH (Secure SHell) is a program for logging 
into and executing commands on a remote machine. SSH is intended to replace 
rlogin and rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and arbitrary 
TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD&#39 s version of the last free version of SSH, bringing
it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.
");
  script_tag(name: "affected", value: "openssh on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-78f0991378");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DWHE7RUOHTJSMFOWW4EUB4CF4CRIPBUO");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~7.4p1~5.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
