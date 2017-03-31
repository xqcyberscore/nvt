###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for obs-service-source_validator openSUSE-SU-2016:1659-1 (obs-service-source_validator)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851352");
  script_version("$Revision: 3619 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-29 13:04:08 +0200 (Wed, 29 Jun 2016) $");
  script_tag(name:"creation_date", value:"2016-06-23 05:24:32 +0200 (Thu, 23 Jun 2016)");
  script_cve_id("CVE-2016-4007");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for obs-service-source_validator openSUSE-SU-2016:1659-1 (obs-service-source_validator)");
  script_tag(name: "summary", value: "Check the version of obs-service-source_validator");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  obs-service-source_validator was updated to fix one security issue.

  This security issue was fixed:
  - CVE-2016-4007: Several maintained source services are vulnerable to
  code/paramter injection (bsc#967265).

  This non-security issue was fixed:
  - bsc#967610: Several occurrences of uninitialized value.");
  script_tag(name: "affected", value: "obs-service-source_validator on openSUSE 13.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2016:1659_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2016-06/msg00049.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of obs-service-source_validator");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"obs-service-source_validator", rpm:"obs-service-source_validator~0.6+git20160531.fbfe336~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
