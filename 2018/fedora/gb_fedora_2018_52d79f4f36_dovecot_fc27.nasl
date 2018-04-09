###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_52d79f4f36_dovecot_fc27.nasl 9396 2018-04-09 04:18:59Z ckuersteiner $
#
# Fedora Update for dovecot FEDORA-2018-52d79f4f36
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
  script_oid("1.3.6.1.4.1.25623.1.0.874321");
  script_version("$Revision: 9396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-09 06:18:59 +0200 (Mon, 09 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 09:01:17 +0200 (Tue, 03 Apr 2018)");
  script_cve_id("CVE-2017-15130", "CVE-2017-14461", "CVE-2017-15132");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for dovecot FEDORA-2018-52d79f4f36");
  script_tag(name: "summary", value: "Check the version of dovecot");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Dovecot is an IMAP server for Linux/UNIX-like 
systems, written with security primarily in mind.  It also contains a small POP3 
server.  It supports mail in either of maildir or mbox formats.

The SQL drivers and authentication plug-ins are in their subpackages.
");
  script_tag(name: "affected", value: "dovecot on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-52d79f4f36");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2MMGWOFO6VBJHZNOUB2WIS7B6GOGH3AP");
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

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.2.34~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
