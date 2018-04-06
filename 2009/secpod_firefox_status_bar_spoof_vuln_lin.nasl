###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_status_bar_spoof_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Firefox Status Bar Spoofing Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful remote exploitation will let the attacker spoof the status
  bar information and can gain sensitive information by redirecting the
  authentic user to any malicious URL.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.0.5 and 2.0.0.18/19 on Linux.";
tag_insight = "Firefox doesn't properly handle the crafted URL which is being displayed in
  the user's browser which lets the attacker perform clickjacking attack and
  can spoof the user redirect to a different arbitrary malformed website.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.getfirefox.com";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to status bar spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900447");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0253");
  script_name("Firefox Status Bar Spoofing Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7842");
  script_xref(name : "URL" , value : "http://security-tracker.debian.net/tracker/CVE-2009-0253");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


firefoxVer = get_kb_item("Firefox/Linux/Ver");
#Check for firefox version 3.0.5 or 2.0.0.18/2.0.0.19
if(firefoxVer =~ "(2.0.0.18|2.0.0.19|3.0.5)"){
  security_message(0);
}
