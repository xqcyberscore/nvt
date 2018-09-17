###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_f56ded11c4_openssh_fc27.nasl 11393 2018-09-14 15:05:24Z bshakeel $
#
# Fedora Update for openssh FEDORA-2018-f56ded11c4
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.875062");
  script_version("$Revision: 11393 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 17:05:24 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-14 07:48:48 +0200 (Fri, 14 Sep 2018)");
  script_cve_id("CVE-2018-15473");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openssh FEDORA-2018-f56ded11c4");
  script_tag(name:"summary", value:"Check the version of openssh");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"SSH (Secure SHell) is a program for logging into
  and executing commands on a remote machine. SSH is intended to replace rlogin and
  rsh, and to provide secure encrypted communications between two untrusted hosts
  over an insecure network. X11 connections and arbitrary TCP/IP ports can also be
  forwarded over the secure channel.

OpenSSH is OpenBSD&#39 s version of the last free version of SSH, bringing
it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.
");
  script_tag(name:"affected", value:"openssh on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-f56ded11c4");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ULKYHCEJIPGOHRZMGZZ5XNTPWI6HCRAL");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~7.6p1~6.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
