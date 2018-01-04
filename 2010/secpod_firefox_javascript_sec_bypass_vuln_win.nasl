###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_javascript_sec_bypass_vuln_win.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Mozilla Firefox 'JavaScript' Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions or manipulate certain data.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.x on Windows.";
tag_insight = "The flaw is due to an error in 'JavaScript' implementation which allows to send
  selected keystrokes to a form field in a hidden frame, instead of the intended
  form field in a visible frame, via certain calls to the focus method.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with firefox browser and is prone to security
  bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902152");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1125");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Mozilla Firefox 'JavaScript' Security Bypass Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/510070/100/0/threaded");
  exit(0);
}


include("version_func.inc");

# Get for Firefox Version
ffVer = get_kb_item("Firefox/Win/Ver");
if(isnull(ffVer)){
  exit(0);
}

# Check for Firefox version 3.0 <= 3.6.2
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.6.2")){
  security_message(0);
}
