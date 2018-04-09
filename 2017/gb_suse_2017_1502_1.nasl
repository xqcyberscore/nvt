###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1502_1.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2017:1502-1 (chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851564");
  script_version("$Revision: 9381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-06-08 06:04:51 +0200 (Thu, 08 Jun 2017)");
  script_cve_id("CVE-2017-5070", "CVE-2017-5071", "CVE-2017-5072", "CVE-2017-5073", 
                  "CVE-2017-5074", "CVE-2017-5075", "CVE-2017-5076", "CVE-2017-5077", "CVE-2017-5078", 
                  "CVE-2017-5079", "CVE-2017-5080", "CVE-2017-5081", "CVE-2017-5082", "CVE-2017-5083", 
                "CVE-2017-5085", "CVE-2017-5086"); 
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2017:1502-1 (chromium)");
  script_tag(name: "summary", value: "Check the version of chromium");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value:"This update to Chromium 59.0.3071.86 fixes 
  the following security issues: - CVE-2017-5070: Type confusion in V8 - 
  CVE-2017-5071: Out of bounds read in V8 - CVE-2017-5072: Address spoofing in 
  Omnibox - CVE-2017-5073: Use after free in print preview - CVE-2017-5074: Use 
  after free in Apps Bluetooth - CVE-2017-5075: Information leak in CSP reporting 
  - CVE-2017-5086: Address spoofing in Omnibox - CVE-2017-5076: Address spoofing 
  in Omnibox - CVE-2017-5077: Heap buffer overflow in Skia - CVE-2017-5078: 
  Possible command injection in mailto handling - CVE-2017-5079: UI spoofing in 
  Blink - CVE-2017-5080: Use after free in credit card autofill - CVE-2017-5081: 
  Extension verification bypass - CVE-2017-5082: Insufficient hardening in credit 
  card editor - CVE-2017-5083: UI spoofing in Blink - CVE-2017-5085: Inappropriate 
  javascript execution on WebUI pages"); 
  script_tag(name: "affected", value: "chromium on openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:1502_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~59.0.3071.86~104.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~59.0.3071.86~104.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~59.0.3071.86~104.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~59.0.3071.86~104.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~59.0.3071.86~104.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}