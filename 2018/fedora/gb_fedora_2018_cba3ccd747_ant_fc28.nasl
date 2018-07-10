###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_cba3ccd747_ant_fc28.nasl 10443 2018-07-06 12:04:26Z santu $
#
# Fedora Update for ant FEDORA-2018-cba3ccd747
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
  script_oid("1.3.6.1.4.1.25623.1.0.874766");
  script_version("$Revision: 10443 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-06 14:04:26 +0200 (Fri, 06 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-05 06:12:31 +0200 (Thu, 05 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ant FEDORA-2018-cba3ccd747");
  script_tag(name:"summary", value:"Check the version of ant");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Apache Ant is a Java library and command-line 
tool whose mission is to drive processes described in build files as targets and 
extension points dependent upon each other.  The main known usage of Ant is the
build of Java applications.  Ant supplies a number of built-in tasks allowing to 
compile, assemble, test and run Java applications.  Ant can also be used 
effectively to build non Java applications, for instance C or C++ applications.  
More generally, Ant can be used to pilot any type of process which can be described 
in terms of targets and tasks.
");
  script_tag(name:"affected", value:"ant on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-cba3ccd747");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/64OG345SY4HCX24PNWXYEJKFRMM2YT6C");
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

  if ((res = isrpmvuln(pkg:"ant", rpm:"ant~1.10.1~10.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
