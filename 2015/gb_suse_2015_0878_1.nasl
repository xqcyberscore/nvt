###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0878_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for flash-player SUSE-SU-2015:0878-1 (flash-player)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851099");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 20:00:42 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-3044", "CVE-2015-3077", "CVE-2015-3078", "CVE-2015-3079", "CVE-2015-3080", "CVE-2015-3081", "CVE-2015-3082", "CVE-2015-3083", "CVE-2015-3084", "CVE-2015-3085", "CVE-2015-3086", "CVE-2015-3087", "CVE-2015-3088", "CVE-2015-3089", "CVE-2015-3090", "CVE-2015-3091", "CVE-2015-3092", "CVE-2015-3093");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for flash-player SUSE-SU-2015:0878-1 (flash-player)");
  script_tag(name: "summary", value: "Check the version of flash-player");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  The Adobe flash-player package was updated to version 11.2.202.460 to fix
  several security issues.

  The following vulnerabilities were fixed (bsc#930677):
  * APSB15-09, CVE-2015-3044, CVE-2015-3077, CVE-2015-3078, CVE-2015-3079,
  CVE-2015-3080, CVE-2015-3081, CVE-2015-3082, CVE-2015-3083,
  CVE-2015-3084, CVE-2015-3085, CVE-2015-3086, CVE-2015-3087,
  CVE-2015-3088, CVE-2015-3089, CVE-2015-3090, CVE-2015-3091,
  CVE-2015-3092, CVE-2015-3093

  More information can be found at the Adobe Security Bulletin APSB15-09:
  https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");
  script_tag(name: "affected", value: "flash-player on SUSE Linux Enterprise Desktop 12");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:0878_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.460~83.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.460~83.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}