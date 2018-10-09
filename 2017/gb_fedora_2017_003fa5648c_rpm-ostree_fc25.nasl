###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for rpm-ostree FEDORA-2017-003fa5648c
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
  script_oid("1.3.6.1.4.1.25623.1.0.872508");
  script_version("$Revision: 11790 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 10:36:59 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-21 05:56:36 +0100 (Tue, 21 Mar 2017)");
  script_cve_id("CVE-2017-2623");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");

  script_name("Fedora Update for rpm-ostree FEDORA-2017-003fa5648c");

  script_tag(name: "summary", value: "Check the version of rpm-ostree");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "rpm-ostree is a hybrid image/package system. 
  It supports 'composing' packages on a build server into an OSTree repository, 
  which can then be replicated by client systems with atomic upgrades. 
  Additionally, unlike many 'pure' image systems, with rpm-ostree each client 
  system can layer on additional packages, providing a 'best of both worlds' 
  approach. ");

  script_tag(name: "affected", value: "rpm-ostree on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-003fa5648c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N3XI7MN7SO2ENMXU3EJNVNWKSLVJZTEC");
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

  if ((res = isrpmvuln(pkg:"rpm-ostree", rpm:"rpm-ostree~2017.3~2.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
