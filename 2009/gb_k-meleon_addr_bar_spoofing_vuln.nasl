###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k-meleon_addr_bar_spoofing_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# K-Meleon Address Bar Spoofing Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation lets the attackers to spoof parts of the
address bar and modify page content on a host that a user may consider partly
trusted.

Impact Level: Application";

tag_affected = "K-Meleon Browser version 1.5.3 on Windows.";

tag_insight = "Address bar can be spoofed via 'window.open()' with a relative
URI, to show an arbitrary URL on the web site visited by the victim, as
demonstrated by a visit to an attacker-controlled web page, which triggers a
spoofed login form for the site containing that page.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with K-Meleon Browser and is prone to
Address Bar Spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800892");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3008");
  script_name("K-Meleon Address Bar Spoofing Vulnerability");
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_k-meleon_detect.nasl");
  script_require_keys("K-Meleon/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

kmeleonVer = get_kb_item("K-Meleon/Ver");
if(kmeleonVer)
{
  # Check for K-Meleon Browser version 1.5.3
  if(version_is_equal(version:kmeleonVer, test_version:"1.5.3")){
    security_message(0);
  }
}
