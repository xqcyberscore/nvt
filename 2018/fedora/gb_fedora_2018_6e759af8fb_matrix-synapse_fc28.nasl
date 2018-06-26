###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_6e759af8fb_matrix-synapse_fc28.nasl 10324 2018-06-26 07:40:01Z santu $
#
# Fedora Update for matrix-synapse FEDORA-2018-6e759af8fb
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
  script_oid("1.3.6.1.4.1.25623.1.0.874725");
  script_version("$Revision: 10324 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 09:40:01 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-24 06:00:21 +0200 (Sun, 24 Jun 2018)");
  script_cve_id("CVE-2018-12291");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for matrix-synapse FEDORA-2018-6e759af8fb");
  script_tag(name:"summary", value:"Check the version of matrix-synapse");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Matrix is an ambitious new ecosystem for open 
federated Instant Messaging and VoIP. Synapse is a reference 'homeserver' 
implementation of Matrix from the core development team at 'http://matrix.org', 
written in Python/Twisted. It is intended to showcase the concept of Matrix and let 
folks see the spec in the context of a coded base and let you run your own homeserver 
and generally help bootstrap the ecosystem.
");
  script_tag(name:"affected", value:"matrix-synapse on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-6e759af8fb");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/R6OJWGSYGZYDEVDCIZH2RNIPI6N5IWPX");
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

  if ((res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~0.31.2~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
