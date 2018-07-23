###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_05acd3c734_openslp_fc28.nasl 10565 2018-07-23 05:20:18Z asteins $
#
# Fedora Update for openslp FEDORA-2018-05acd3c734
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
  script_oid("1.3.6.1.4.1.25623.1.0.874829");
  script_version("$Revision: 10565 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-23 07:20:18 +0200 (Mon, 23 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-20 06:06:18 +0200 (Fri, 20 Jul 2018)");
  script_cve_id("CVE-2017-17833");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openslp FEDORA-2018-05acd3c734");
  script_tag(name:"summary", value:"Check the version of openslp");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is 
present on the target host.");
  script_tag(name:"insight", value:"Service Location Protocol is an IETF 
standards track protocol that provides a framework to allow networking 
applications to discover the existence, location, and configuration of 
networked services in enterprise networks.

OpenSLP is an open source implementation of the SLPv2 protocol as defined
by RFC 2608 and RFC 2614.
");
  script_tag(name:"affected", value:"openslp on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-05acd3c734");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H4WB4SKVDGCKX5FZGDSCL7VOCERVQDS3");
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

  if ((res = isrpmvuln(pkg:"openslp", rpm:"openslp~2.0.0~18.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
