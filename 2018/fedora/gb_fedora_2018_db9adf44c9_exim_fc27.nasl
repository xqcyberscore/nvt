###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_db9adf44c9_exim_fc27.nasl 9214 2018-03-27 08:11:34Z santu $
#
# Fedora Update for exim FEDORA-2018-db9adf44c9
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
  script_oid("1.3.6.1.4.1.25623.1.0.874270");
  script_version("$Revision: 9214 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-27 10:11:34 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-25 08:28:14 +0200 (Sun, 25 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for exim FEDORA-2018-db9adf44c9");
  script_tag(name: "summary", value: "Check the version of exim");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Exim is a message transfer agent (MTA) 
developed at the University of Cambridge for use on Unix systems connected to 
the Internet. It is freely available under the terms of the GNU General Public 
Licence. In style it is similar to Smail 3, but its facilities are more general. 
There is a great deal of flexibility in the way mail can be routed, and there 
are extensive facilities for checking incoming mail. Exim can be installed in 
place of sendmail, although the configuration of exim is quite different to that 
of sendmail.
");
  script_tag(name: "affected", value: "exim on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-db9adf44c9");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HGA2TQLHUI3VT6VXZRSZZLVW3HTIXIGB");
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

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.90.1~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
