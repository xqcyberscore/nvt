###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_6db422c637_matrix-synapse_fc28.nasl 11471 2018-09-19 11:17:08Z santu $
#
# Fedora Update for matrix-synapse FEDORA-2018-6db422c637
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
  script_oid("1.3.6.1.4.1.25623.1.0.875069");
  script_version("$Revision: 11471 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 13:17:08 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-15 07:42:17 +0200 (Sat, 15 Sep 2018)");
  script_cve_id("CVE-2018-16515", "CVE-2018-12291");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for matrix-synapse FEDORA-2018-6db422c637");
  script_tag(name:"summary", value:"Check the version of matrix-synapse");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Matrix is an ambitious new ecosystem for open
  federated Instant Messaging and VoIP. Synapse is a reference 'homeserver'
  implementation of Matrix from the core development team at 'http://matrix.org',
  written in Python/Twisted. It is intended to showcase the concept of Matrix and
  let folks see the spec in the context of a coded base and let you run your own
  homeserver and generally help bootstrap the ecosystem.
");
  script_tag(name:"affected", value:"matrix-synapse on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-6db422c637");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IRW7YR2H3ASUSYX4AO4KMY3FNVDNYW3P");
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

  if ((res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~0.33.3.1~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
