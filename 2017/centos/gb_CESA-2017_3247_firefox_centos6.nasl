###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_3247_firefox_centos6.nasl 7856 2017-11-22 05:28:21Z santu $
#
# CentOS Update for firefox CESA-2017:3247 centos6 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882801");
  script_version("$Revision: 7856 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 06:28:21 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-18 07:32:28 +0100 (Sat, 18 Nov 2017)");
  script_cve_id("CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7830");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2017:3247 centos6 ");
  script_tag(name: "summary", value: "Check the version of firefox");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.5.0 ESR.

Security Fix(es):

* Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2017-7826, CVE-2017-7828, CVE-2017-7830)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, David Keeler, Jon Coppeard, Julien
Cristau, Jan de Mooij, Jason Kratzer, Philipp, Nicholas Nethercote, Oriol
Brufau, Andre Bargull, Bob Clary, Jet Villegas, Randell Jesup, Tyson Smith,
Gary Kwong, Ryan VanderMeulen, Nils, and Jun Kokatsu as the original
reporters.
");
  script_tag(name: "affected", value: "firefox on CentOS 6");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "CESA", value: "2017:3247");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2017-November/022627.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~52.5.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
