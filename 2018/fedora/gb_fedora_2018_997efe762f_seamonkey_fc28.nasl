###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_997efe762f_seamonkey_fc28.nasl 10849 2018-08-09 07:20:42Z santu $
#
# Fedora Update for seamonkey FEDORA-2018-997efe762f
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
  script_oid("1.3.6.1.4.1.25623.1.0.874904");
  script_version("$Revision: 10849 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 09:20:42 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 06:05:30 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for seamonkey FEDORA-2018-997efe762f");
  script_tag(name:"summary", value:"Check the version of seamonkey");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"SeaMonkey is an all-in-one Internet application 
suite. It includes a browser, mail/news client, IRC client, JavaScript debugger, 
and a tool to inspect the DOM for web pages. It is derived from the application 
formerly known as Mozilla Application Suite.");
  script_tag(name:"affected", value:"seamonkey on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-997efe762f");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ELET6RS2JYYRNOAH3EW4WLAOGD7MS6ER");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.49.4~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
