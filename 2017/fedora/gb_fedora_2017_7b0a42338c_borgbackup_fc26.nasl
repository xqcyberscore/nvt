###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_7b0a42338c_borgbackup_fc26.nasl 8085 2017-12-12 10:25:30Z santu $
#
# Fedora Update for borgbackup FEDORA-2017-7b0a42338c
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
  script_oid("1.3.6.1.4.1.25623.1.0.873898");
  script_version("$Revision: 8085 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-12 11:25:30 +0100 (Tue, 12 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-11 08:05:03 +0100 (Mon, 11 Dec 2017)");
  script_cve_id("CVE-2017-15914");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for borgbackup FEDORA-2017-7b0a42338c");
  script_tag(name: "summary", value: "Check the version of borgbackup");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "BorgBackup (short: Borg) is a deduplicating 
backup program. Optionally, it supports compression and authenticated encryption.");
  script_tag(name: "affected", value: "borgbackup on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-7b0a42338c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A4D3QBZKM2YQP2PRRS32IDHJ4RUDYCBL");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"borgbackup", rpm:"borgbackup~1.1.3~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
