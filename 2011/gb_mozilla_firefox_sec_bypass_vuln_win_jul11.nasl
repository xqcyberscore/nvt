###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_sec_bypass_vuln_win_jul11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Firefox Security Bypass Vulnerability July-11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote attackers to trigger an installation
  dialog for a add-on or theme.
  Impact Level: Application";
tag_affected = "Mozilla Firefox versions before 5.0.";
tag_insight = "The flaw is due to firefox does not properly enforce the whitelist
  for the xpinstall functionality, which allows a non-whitelisted site to
  trigger an install dialog for add-ons and themes.";
tag_solution = "Upgrade to Firefox version 5.0 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802215");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-2370");
  script_bugtraq_id(48380);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Mozilla Firefox Security Bypass Vulnerability July-11 (Windows)");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=645699");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-28.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox versions before 5.0
  if(version_is_less(version:ffVer, test_version:"5.0")){
    security_message(0);
  }
}
