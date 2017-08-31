###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for cracklib FEDORA-2016-bfa785e39e
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
  script_oid("1.3.6.1.4.1.25623.1.0.872129");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-12-12 06:27:21 +0100 (Mon, 12 Dec 2016)");
  script_cve_id("CVE-2016-6318");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for cracklib FEDORA-2016-bfa785e39e");
  script_tag(name: "summary", value: "Check the version of cracklib");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "CrackLib tests passwords to determine
  whether they match certain security-oriented characteristics, with the
  purpose of stopping users from choosing passwords that are easy to guess.
  CrackLib performs several tests on passwords: it tries to generate words
  from a username and gecos entry and checks those words against the password
   it checks for simplistic patterns in passwords  and it checks for the
  password in a dictionary.

  CrackLib is actually a library containing a particular C function
  which is used to check the password, as well as other C
  functions. CrackLib is not a replacement for a passwd program  it must
  be used in conjunction with an existing passwd program.

  Install the cracklib package if you need a program to check users&#39 
  passwords to see if they are at least minimally secure. If you install
  CrackLib, you will also want to install the cracklib-dicts package.");

  script_tag(name: "affected", value: "cracklib on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-bfa785e39e");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OFHOEZLXO4GLXI6PSLK5J2GX5D6GZ4DH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"cracklib", rpm:"cracklib~2.9.6~4.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
