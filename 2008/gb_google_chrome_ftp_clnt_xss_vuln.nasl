###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_ftp_clnt_xss_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Google Chrome Web Browser FTP Client XSS Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful remote attack result in injection of arbitrary web
  script or HTML code.
  Impact Level: Application";
tag_affected = "Google Chrome version 0.2.149 30 and prior on all running platform.";
tag_insight = "The flaw is due to the way browser handles web script or html via
  ftp://URL for an html document within a JPG, PDF, or TXT files.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.
For updates refer to https://www.google.com/intl/en/chrome/browser ";
tag_summary = "The host is installed with Goole Chrome Web Browser and is prone to
  Cross Site Scripting (XSS) Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800121");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-4724");
  script_bugtraq_id(31855);
  script_name("Google Chrome Web Browser FTP Client XSS Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/31855");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"0.2.149.30")){
  security_message(0);
}
