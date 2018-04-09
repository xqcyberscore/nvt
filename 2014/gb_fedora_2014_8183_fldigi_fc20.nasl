###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for fldigi FEDORA-2014-8183
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.867993");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-07-28 16:12:36 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-3970");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Fedora Update for fldigi FEDORA-2014-8183");

  tag_insight = "Fldigi is a modem program which supports most of the digital modes used by
ham radio operators today. You can also use the program for calibrating your
sound card to WWV or doing a frequency measurement test. The program also comes
with a CW decoder. fldigi is written with the help of the Fast Light Toolkit X
GUI. Fldigi is a fast moving project many added features with each update.

Flarq (Fast Light Automatic Repeat Request) is a file transfer application
that is based on the ARQ specification developed by Paul Schmidt, K9PS.
It is capable of transmitting and receiving frames of ARQ data via fldigi.

The fldigi-shell program controls fldigi over HTTP via XML-encoded
remote procedure calls (XML-RPC). It can call any XML-RPC method
exported by fldigi, and also defines some useful commands of its own.
";

  tag_affected = "fldigi on Fedora 20";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2014-8183");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136013.html");
  script_tag(name:"summary", value:"Check for the Version of fldigi");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"fldigi", rpm:"fldigi~3.21.83~2.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}