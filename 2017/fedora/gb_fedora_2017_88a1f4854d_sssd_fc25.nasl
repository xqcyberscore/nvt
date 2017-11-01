###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_88a1f4854d_sssd_fc25.nasl 7601 2017-10-31 06:41:32Z santu $
#
# Fedora Update for sssd FEDORA-2017-88a1f4854d
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873546");
  script_version("$Revision: 7601 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-31 07:41:32 +0100 (Tue, 31 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-27 20:55:20 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-12173");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for sssd FEDORA-2017-88a1f4854d");
  script_tag(name: "summary", value: "Check the version of sssd");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Provides a set of daemons to manage access 
to remote directories and authentication mechanisms. It provides an NSS and PAM 
interface toward the system and a plug-gable back-end system to connect to multiple 
different account sources. It is also the basis to provide client auditing and policy
services for projects like FreeIPA.

The sssd sub-package is a meta-package that contains the daemon as well as all
the existing back ends.
");
  script_tag(name: "affected", value: "sssd on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-88a1f4854d");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LHN6IKEAN3RCLYIH66T52I77IVZKBJ33");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.15.3~5.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
