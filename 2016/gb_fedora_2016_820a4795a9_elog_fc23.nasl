###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for elog FEDORA-2016-820a4795a9
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809243");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-09-10 06:03:38 +0200 (Sat, 10 Sep 2016)");
  script_cve_id("CVE-2016-6342");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for elog FEDORA-2016-820a4795a9");
  script_tag(name: "summary", value: "Check the version of elog");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "ELOG is part of a family of applications
  known as weblogs. Their general purpose is:

  1. To make it easy for people to put information online in a chronological
  fashion, in the form of short, time-stamped text messages ('entries') with
  optional HTML markup for presentation, and optional file attachments
  (images, archives, etc.)

  2. To make it easy for other people to access this information through a
  Web interface, browse entries, search, download files, and optionally add,
  update, delete or comment on entries.

  ELOG is a remarkable implementation of a weblog in at least two respects:

  1. Its simplicity of use: you don&#39 t need to be a seasoned server operator
  and/or an experimented database administrator to run ELOG   one executable
  file (under Unix or Windows), a simple configuration text file, and it works.
  No Web server or relational database required. It is also easy to translate
  the interface to the appropriate language for your users.

  2. Its versatility: through its single configuration file, ELOG can be made
  to display an infinity of variants of the weblog concept. There are options
  for what to display, how to display it, what commands are available and to
  whom, access control, etc. Moreover, a single server can host several
  weblogs, and each weblog can be totally different from the rest.");

  script_tag(name: "affected", value: "elog on Fedora 23");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-820a4795a9");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MZ554SODI3GJ6I56XJJFQBHXJTWFRBAH");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC23")
{

  if ((res = isrpmvuln(pkg:"elog", rpm:"elog~3.1.1~7.fc23", rls:"FC23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
