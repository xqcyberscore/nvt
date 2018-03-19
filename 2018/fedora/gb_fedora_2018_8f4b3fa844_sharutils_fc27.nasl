###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_8f4b3fa844_sharutils_fc27.nasl 9117 2018-03-16 13:48:01Z santu $
#
# Fedora Update for sharutils FEDORA-2018-8f4b3fa844
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
  script_oid("1.3.6.1.4.1.25623.1.0.874209");
  script_version("$Revision: 9117 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-16 14:48:01 +0100 (Fri, 16 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 08:41:11 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for sharutils FEDORA-2018-8f4b3fa844");
  script_tag(name: "summary", value: "Check the version of sharutils");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The sharutils package contains the GNU 
shar utilities, a set of tools for encoding and decoding packages of files 
(in binary or text format) in a special plain text format called shell archives 
(shar).  This format can be sent through e-mail (which can be problematic for 
regular binary files).  The shar utility supports a wide range of capabilities 
(compressing, uuencoding, splitting long files for multi-part mailings, providing 
check-sums), which make it very flexible at creating shar files.  After the files 
have been sent, the unshar tool scans mail messages looking for shar files.  
Unshar automatically strips off mail headers and introductory text and then unpacks
the shar files.
");
  script_tag(name: "affected", value: "sharutils on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-8f4b3fa844");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LSTLNKMVXDRS7L32VJ5TIEL4Q4PVSGNE");
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

  if ((res = isrpmvuln(pkg:"sharutils", rpm:"sharutils~4.15.2~8.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
