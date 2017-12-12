###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2496_1.nasl 8047 2017-12-08 08:56:07Z santu $
#
# SuSE Update for nodejs openSUSE-SU-2016:2496-1 (nodejs)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851406");
  script_version("$Revision: 8047 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:56:07 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-10-12 05:46:13 +0200 (Wed, 12 Oct 2016)");
  script_cve_id("CVE-2016-1669", "CVE-2016-2178", "CVE-2016-2183", "CVE-2016-5325", 
                "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7099");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for nodejs openSUSE-SU-2016:2496-1 (nodejs)");
  script_tag(name: "summary", value: "Check the version of nodejs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update brings the new upstream nodejs LTS version 4.6.0, fixing bugs
  and security issues:

  * Nodejs embedded openssl version update
  + upgrade to 1.0.2j (CVE-2016-6304, CVE-2016-2183, CVE-2016-2178,
  CVE-2016-6306, CVE-2016-7052)
  + remove support for dynamic 3rd party engine modules
  * http: Properly validate for allowable characters in input user data.
  This introduces a new case where throw may occur when configuring HTTP
  responses, users should already be adopting try/catch here.
  (CVE-2016-5325, bsc#985201)
  * tls: properly validate wildcard certificates (CVE-2016-7099, bsc#1001652)
  * buffer: Zero-fill excess bytes in new Buffer objects created with
  Buffer.concat()");
  script_tag(name: "affected", value: "nodejs on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2016:2496_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~4.6.0~24.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-debuginfo", rpm:"nodejs-debuginfo~4.6.0~24.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-debugsource", rpm:"nodejs-debugsource~4.6.0~24.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~4.6.0~24.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-doc", rpm:"nodejs-doc~4.6.0~24.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
